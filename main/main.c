/**
 * @file main.c
 * @brief FirmGuard-BLE Security & Telemetry Firmware
 *
 * Implements continuous Bluetooth Low Energy (BLE) surveillance scanning,
 * visual alert actuation on GPIO 2, an asynchronous security lockdown override
 * on GPIO 0 via hardware ISR, and a 1000ms periodic live telemetry stream over UART0.
 *
 * Target: ESP32-WROOM-32 / ESP32-DevKitC
 * Framework: ESP-IDF v5.5 (FreeRTOS 1000 Hz, Apache NimBLE)
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

/* FreeRTOS includes */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

/* ESP-IDF system and hardware drivers */
#include "esp_system.h"
#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "driver/gpio.h"

/* NimBLE BLE Host and Controller Stack */
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"

/* -------------------------------------------------------------------------- */
/* Hardware Configuration & Constants                                         */
/* -------------------------------------------------------------------------- */

#define TAG                         "FIRMGUARD_BLE"

#define GPIO_THREAT_LED             GPIO_NUM_2
#define GPIO_LOCKDOWN_BTN           GPIO_NUM_0

#define BLE_RSSI_THREAT_THRESHOLD   (-75)       /* dBm: signals >= -75 are classified as proximity threats */
#define THREAT_HOLD_TIME_US         (3000000)   /* 3.0 seconds in microseconds */
#define TELEMETRY_INTERVAL_MS       (1000)      /* 1.0 second deterministic reporting cadence */
#define DEBOUNCE_DELAY_MS           (250)       /* Hardware button debounce time */
#define MUTEX_TIMEOUT_MS            (50)        /* Bounded mutex wait time to avoid priority inversion */

/* -------------------------------------------------------------------------- */
/* System State Data Structures                                               */
/* -------------------------------------------------------------------------- */

typedef struct {
    uint32_t scanned_total_count;
    uint32_t threats_detected_count;
    bool threat_active;
    bool lockdown_active;
    char last_mac[18];
    int8_t last_rssi;
    int64_t last_threat_timestamp_us;
} firmguard_state_t;

/* Global state protected by FreeRTOS binary mutex */
static firmguard_state_t g_firmguard_state = {
    .scanned_total_count = 0,
    .threats_detected_count = 0,
    .threat_active = false,
    .lockdown_active = false,
    .last_mac = "00:00:00:00:00:00",
    .last_rssi = -128,
    .last_threat_timestamp_us = 0
};

static SemaphoreHandle_t s_state_mutex = NULL;
static SemaphoreHandle_t s_lockdown_sem = NULL;

/* -------------------------------------------------------------------------- */
/* Forward Declarations                                                       */
/* -------------------------------------------------------------------------- */

static void ble_scan_start(void);
static int ble_gap_event_handler(struct ble_gap_event *event, void *arg);
static void ble_on_sync(void);
static void ble_on_reset(int reason);
static void nimble_host_task(void *param);

static void vLiveIntelligenceTelemetryTask(void *pvParameters);
static void vLockdownManagerTask(void *pvParameters);
static void IRAM_ATTR gpio_0_isr_handler(void *arg);

/* -------------------------------------------------------------------------- */
/* Helper Functions                                                           */
/* -------------------------------------------------------------------------- */

/**
 * @brief Formats raw 6-byte BLE MAC address into standard colon-separated hex string.
 */
static void format_mac_address(const uint8_t *addr, char *out_str, size_t max_len)
{
    snprintf(out_str, max_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
}

/**
 * @brief Updates hardware LED indicator based on threat and lockdown status.
 */
static void update_threat_led(bool threat_active, bool lockdown_active)
{
    if (lockdown_active) {
        /* In Lockdown mode, LED is strictly forced OFF for visual covertness */
        gpio_set_level(GPIO_THREAT_LED, 0);
    } else {
        /* Normal mode: illuminate LED when threat is active */
        gpio_set_level(GPIO_THREAT_LED, threat_active ? 1 : 0);
    }
}

/* -------------------------------------------------------------------------- */
/* Interrupt Service Routine (ISR) Implementation                             */
/* -------------------------------------------------------------------------- */

/**
 * @brief GPIO 0 Falling Edge Interrupt Handler (BOOT button depress).
 * Non-blocking, runs in IRAM context, defers processing to vLockdownManagerTask.
 */
static void IRAM_ATTR gpio_0_isr_handler(void *arg)
{
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    if (s_lockdown_sem != NULL) {
        xSemaphoreGiveFromISR(s_lockdown_sem, &xHigherPriorityTaskWoken);
        if (xHigherPriorityTaskWoken == pdTRUE) {
            portYIELD_FROM_ISR();
        }
    }
}

/* -------------------------------------------------------------------------- */
/* FreeRTOS Tasks                                                             */
/* -------------------------------------------------------------------------- */

/**
 * @brief Lockdown Management Task
 * Handles debounced transition of security lockdown override when button is triggered.
 */
static void vLockdownManagerTask(void *pvParameters)
{
    ESP_LOGI(TAG, "Lockdown manager task online.");

    while (1) {
        if (xSemaphoreTake(s_lockdown_sem, portMAX_DELAY) == pdTRUE) {
            /* Debounce delay */
            vTaskDelay(pdMS_TO_TICKS(DEBOUNCE_DELAY_MS));

            /* Check pin state to verify actual physical depression */
            if (gpio_get_level(GPIO_LOCKDOWN_BTN) == 0) {
                if (xSemaphoreTake(s_state_mutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) == pdTRUE) {
                    g_firmguard_state.lockdown_active = !g_firmguard_state.lockdown_active;
                    bool current_lockdown = g_firmguard_state.lockdown_active;
                    bool current_threat = g_firmguard_state.threat_active;
                    xSemaphoreGive(s_state_mutex);

                    update_threat_led(current_threat, current_lockdown);

                    if (current_lockdown) {
                        ESP_LOGW(TAG, ">>> SECURITY LOCKDOWN ENGAGED - ALERTS SUPPRESSED <<<");
                    } else {
                        ESP_LOGI(TAG, ">>> SECURITY LOCKDOWN DISENGAGED - NORMAL SURVEILLANCE <<<");
                    }
                }
            }

            /* Clear any queue backlogs accumulated during debounce */
            xSemaphoreTake(s_lockdown_sem, 0);
        }
    }
}

/**
 * @brief Live Intelligence Telemetry Task (REQ-04)
 * Streams RFC 8259-compliant JSON telemetry records over UART0 at a deterministic 1000ms cadence.
 */
static void vLiveIntelligenceTelemetryTask(void *pvParameters)
{
    TickType_t xLastWakeTime = xTaskGetTickCount();
    const TickType_t xFrequency = pdMS_TO_TICKS(TELEMETRY_INTERVAL_MS);

    ESP_LOGI(TAG, "Live intelligence telemetry task online (Interval: %d ms).", TELEMETRY_INTERVAL_MS);

    while (1) {
        /* Deterministic 1 Hz wake-up */
        vTaskDelayUntil(&xLastWakeTime, xFrequency);

        int64_t current_time_us = esp_timer_get_time();
        firmguard_state_t snapshot;
        bool state_acquired = false;

        if (xSemaphoreTake(s_state_mutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) == pdTRUE) {
            /* Evaluate threat hold expiration */
            if (g_firmguard_state.threat_active) {
                if ((current_time_us - g_firmguard_state.last_threat_timestamp_us) > THREAT_HOLD_TIME_US) {
                    g_firmguard_state.threat_active = false;
                    update_threat_led(false, g_firmguard_state.lockdown_active);
                }
            }

            /* Create thread-safe local snapshot */
            memcpy(&snapshot, &g_firmguard_state, sizeof(firmguard_state_t));
            xSemaphoreGive(s_state_mutex);
            state_acquired = true;
        }

        if (state_acquired) {
            uint64_t uptime_ms = (uint64_t)(current_time_us / 1000);
            uint32_t free_heap = esp_get_free_heap_size();

            /* Emit strictly formatted, single-line JSON string over UART0 */
            printf("{\"uptime_ms\":%" PRIu64 ",\"scanned_count\":%" PRIu32 ",\"threat_count\":%" PRIu32 ",\"threat_active\":%s,\"lockdown_active\":%s,\"last_mac\":\"%s\",\"last_rssi\":%d,\"free_heap\":%" PRIu32 "}\n",
                   uptime_ms,
                   snapshot.scanned_total_count,
                   snapshot.threats_detected_count,
                   snapshot.threat_active ? "true" : "false",
                   snapshot.lockdown_active ? "true" : "false",
                   snapshot.last_mac,
                   snapshot.last_rssi,
                   free_heap);
            fflush(stdout);
        } else {
            ESP_LOGW(TAG, "Telemetry skipped: state mutex busy.");
        }
    }
}

/* -------------------------------------------------------------------------- */
/* NimBLE BLE GAP Discovery Engine                                           */
/* -------------------------------------------------------------------------- */

/**
 * @brief NimBLE GAP Event Callback
 * Evaluates discovery events for threat indicators and updates global intelligence state.
 */
static int ble_gap_event_handler(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
        char addr_str[18];
        format_mac_address(event->disc.addr.val, addr_str, sizeof(addr_str));
        int8_t rssi = event->disc.rssi;
        bool is_threat = (rssi >= BLE_RSSI_THREAT_THRESHOLD);
        int64_t now_us = esp_timer_get_time();

        if (xSemaphoreTake(s_state_mutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) == pdTRUE) {
            g_firmguard_state.scanned_total_count++;
            strncpy(g_firmguard_state.last_mac, addr_str, sizeof(g_firmguard_state.last_mac) - 1);
            g_firmguard_state.last_mac[sizeof(g_firmguard_state.last_mac) - 1] = '\0';
            g_firmguard_state.last_rssi = rssi;

            if (is_threat) {
                g_firmguard_state.threats_detected_count++;
                g_firmguard_state.threat_active = true;
                g_firmguard_state.last_threat_timestamp_us = now_us;
            }

            bool threat_active = g_firmguard_state.threat_active;
            bool lockdown_active = g_firmguard_state.lockdown_active;
            xSemaphoreGive(s_state_mutex);

            /* Actuate hardware indicator */
            update_threat_led(threat_active, lockdown_active);
        }
        return 0;
    }

    case BLE_GAP_EVENT_DISC_COMPLETE:
        ESP_LOGI(TAG, "Discovery cycle ended; re-arming scan engine.");
        ble_scan_start();
        return 0;

    default:
        return 0;
    }
}

/**
 * @brief Configures and initiates continuous BLE passive scanning.
 */
static void ble_scan_start(void)
{
    struct ble_gap_disc_params disc_params;
    memset(&disc_params, 0, sizeof(disc_params));

    /* Continuous 100% duty-cycle scanning (160 * 0.625ms = 100ms) */
    disc_params.itvl = 160;
    disc_params.window = 160;
    disc_params.passive = 1;
    disc_params.filter_policy = BLE_HCI_SCAN_FILT_NO_WL;
    disc_params.filter_duplicates = 0; /* Continuous live monitoring */
    disc_params.limited = 0;

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, ble_gap_event_handler, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "Failed to start BLE discovery procedure; rc=%d", rc);
    } else {
        ESP_LOGI(TAG, "BLE continuous surveillance scan active.");
    }
}

static void ble_on_sync(void)
{
    ESP_LOGI(TAG, "NimBLE host synchronized with controller baseband.");
    ble_scan_start();
}

static void ble_on_reset(int reason)
{
    ESP_LOGE(TAG, "NimBLE stack reset occurred; reason=%d", reason);
}

static void nimble_host_task(void *param)
{
    ESP_LOGI(TAG, "NimBLE host task executing.");
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/* -------------------------------------------------------------------------- */
/* Hardware Initialization Subroutines                                        */
/* -------------------------------------------------------------------------- */

/**
 * @brief Configures GPIO 2 (Alert LED) and GPIO 0 (Lockdown Button).
 */
static esp_err_t init_hardware_gpios(void)
{
    /* Configure GPIO 2 as digital output */
    gpio_config_t io_conf_led = {
        .pin_bit_mask = (1ULL << GPIO_THREAT_LED),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    esp_err_t err = gpio_config(&io_conf_led);
    if (err != ESP_OK) return err;
    gpio_set_level(GPIO_THREAT_LED, 0);

    /* Configure GPIO 0 as digital input with pull-up and falling-edge interrupt */
    gpio_config_t io_conf_btn = {
        .pin_bit_mask = (1ULL << GPIO_LOCKDOWN_BTN),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_NEGEDGE
    };
    err = gpio_config(&io_conf_btn);
    if (err != ESP_OK) return err;

    /* Install ISR service */
    err = gpio_install_isr_service(0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }

    err = gpio_isr_handler_add(GPIO_LOCKDOWN_BTN, gpio_0_isr_handler, NULL);
    return err;
}

/**
 * @brief Resilient Non-Volatile Storage (NVS) initialization (REQ-05).
 */
static void init_nvs_resilient(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition corrupted or new version detected. Erasing partition...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_LOGI(TAG, "NVS flash system successfully initialized.");
}

/* -------------------------------------------------------------------------- */
/* Application Entry Point                                                    */
/* -------------------------------------------------------------------------- */

void app_main(void)
{
    ESP_LOGI(TAG, "=================================================");
    ESP_LOGI(TAG, "  FirmGuard-BLE Embedded Security System v1.0.0  ");
    ESP_LOGI(TAG, "  Target: ESP32-WROOM-32 | ESP-IDF v5.5          ");
    ESP_LOGI(TAG, "=================================================");

    /* Step 1: Resilient NVS Initialization (REQ-05) */
    init_nvs_resilient();

    /* Step 2: Synchronization Primitives (REQ-06) */
    s_state_mutex = xSemaphoreCreateMutex();
    assert(s_state_mutex != NULL);

    s_lockdown_sem = xSemaphoreCreateBinary();
    assert(s_lockdown_sem != NULL);

    /* Step 3: Hardware GPIO & ISR Initialization (REQ-02, REQ-03) */
    ESP_ERROR_CHECK(init_hardware_gpios());
    ESP_LOGI(TAG, "Hardware GPIOs and ISR routines configured successfully.");

    /* Step 4: Launch Management Tasks */
    BaseType_t task_ret = xTaskCreatePinnedToCore(
        vLockdownManagerTask,
        "vLockdownMgr",
        3072,
        NULL,
        configMAX_PRIORITIES - 2,
        NULL,
        1
    );
    assert(task_ret == pdPASS);

    task_ret = xTaskCreatePinnedToCore(
        vLiveIntelligenceTelemetryTask,
        "vTelemetryTask",
        4096,
        NULL,
        configMAX_PRIORITIES - 3,
        NULL,
        1
    );
    assert(task_ret == pdPASS);

    /* Step 5: NimBLE Host & Controller Initialization (REQ-01) */
    ESP_ERROR_CHECK(nimble_port_init());

    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_hs_cfg.reset_cb = ble_on_reset;

    nimble_port_freertos_init(nimble_host_task);
    ESP_LOGI(TAG, "FirmGuard-BLE initialization sequence complete. System Armed.");
}
