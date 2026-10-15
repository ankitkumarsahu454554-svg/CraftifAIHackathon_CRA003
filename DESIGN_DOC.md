# FirmGuard-BLE System Design Document

**Firmware Version**: 1.0.0  
**Target Architecture**: Espressif ESP32 (Xtensa Dual-Core 32-bit LX6 @ 240 MHz)  
**RTOS / Framework**: ESP-IDF v5.5 / Apache NimBLE  
**Author**: Antigravity Firmware Team  

---

## 1. System Overview

FirmGuard-BLE is an embedded hardware security node designed to detect, classify, and report unauthorized Bluetooth Low Energy (BLE) tracking devices and beacons operating within physical proximity. The system combines:
1. Continuous passive/active BLE radio spectrum scanning using Apache NimBLE.
2. Immediate edge actuation via an onboard visual threat LED on GPIO 2.
3. An asynchronous security lockdown override via a hardware falling-edge ISR on GPIO 0.
4. A deterministic 1 Hz live JSON telemetry stream broadcast over UART0 at 115200 baud.

---

## 2. Hardware Pin Mapping

The firmware maps to standard ESP32 development modules (e.g. ESP32-WROOM-32, NodeMCU-32S, ESP32-DevKitC v4):

| GPIO Number | Signal Name | Electrical Characteristics | Target Peripheral / Circuit Connection |
|:---|:---|:---|:---|
| **GPIO 2** | `GPIO_THREAT_LED` | Digital Output, Push-Pull, 3.3V, Current Sourcing up to 12mA | Onboard Blue LED (Series resistor 470Ω to GND) / External Alarm Relay Buffer |
| **GPIO 0** | `GPIO_LOCKDOWN_BTN`| Digital Input, Internal Pull-Up (~45kΩ enabled), Falling-Edge Interrupt | Onboard tactile "BOOT" pushbutton connected to GND / External Security Switch |
| **GPIO 1** | `UART0_TXD` | Digital Output, 115200 Baud, 8N1 | Silicon Labs CP2102 or CH340 USB-to-UART Bridge TX line to Host PC |
| **GPIO 3** | `UART0_RXD` | Digital Input, 115200 Baud, 8N1 | Silicon Labs CP2102 or CH340 USB-to-UART Bridge RX line from Host PC |

---

## 3. Architecture Diagrams

### 3.1 High-Level Subsystem Architecture

```mermaid
graph TD
    subgraph RF_Domain["Radio Frequency Domain (2.4 GHz)"]
        BLE_Adv["BLE Advertisements (Ch 37, 38, 39)"]
    end

    subgraph ESP32_Core0["ESP32 Core 0: Wireless Baseband"]
        NimBLE_Stack["Apache NimBLE Host & Controller"]
        GAP_Scanner["GAP Discovery Engine (100% Duty Cycle)"]
    end

    subgraph ESP32_Core1["ESP32 Core 1: Security Application & Telemetry"]
        GPIO0_ISR["GPIO 0 Falling-Edge ISR (IRAM)"]
        Lockdown_Task["vLockdownManagerTask"]
        Telemetry_Task["vLiveIntelligenceTelemetryTask (1000ms Cadence)"]
        State_Mgr["Shared System State (Thread-Safe Mutex)"]
        GPIO2_Driver["GPIO 2 Actuator Driver"]
    end

    subgraph External_Peripherals["Physical I/O Peripherals"]
        BOOT_BTN["Tactile BOOT Switch (GPIO 0)"]
        ALARM_LED["Threat Visual LED (GPIO 2)"]
        UART_PORT["UART0 Serial Output (115200 8N1)"]
    end

    BLE_Adv --> NimBLE_Stack
    NimBLE_Stack --> GAP_Scanner
    GAP_Scanner --"RSSI & MAC"--> State_Mgr
    GAP_Scanner --"Trigger Alert"--> GPIO2_Driver

    BOOT_BTN --> GPIO0_ISR
    GPIO0_ISR --"xSemaphoreGiveFromISR"--> Lockdown_Task
    Lockdown_Task --"Toggle Lockdown"--> State_Mgr
    Lockdown_Task --"Force Low (Covert)"--> GPIO2_Driver

    State_Mgr --> Telemetry_Task
    Telemetry_Task --"JSON Record"--> UART_PORT
    GPIO2_Driver --> ALARM_LED
```

---

### 3.2 Finite State Machine (FSM)

```mermaid
stateDiagram-v2
    [*] --> SYSTEM_BOOT: Power On / Reset

    state SYSTEM_BOOT {
        [*] --> NVS_INIT: nvs_flash_init()
        NVS_INIT --> GPIO_INIT: Configure GPIO 0 & GPIO 2
        GPIO_INIT --> IPC_INIT: Create Mutex & Semaphores
        IPC_INIT --> TASKS_INIT: Launch Telemetry & Lockdown Tasks
        TASKS_INIT --> NIMBLE_SYNC: ble_gap_disc()
    }

    SYSTEM_BOOT --> IDLE_SCANNING: Baseband Synchronized

    state IDLE_SCANNING {
        [*] --> SCAN_WAIT: 100% Duty Cycle
        SCAN_WAIT --> PACKET_RECEIVED: Adv Packet Detected
        PACKET_RECEIVED --> RSSI_EVAL: Check RSSI >= -75 dBm
        RSSI_EVAL --> SCAN_WAIT: RSSI < -75 dBm (Ignored)
    }

    IDLE_SCANNING --> THREAT_ACTIVE: RSSI >= -75 dBm detected
    
    state THREAT_ACTIVE {
        LED_ON: GPIO 2 = HIGH
        TIMER_RUNNING: Expiry window 3000ms active
    }

    THREAT_ACTIVE --> THREAT_ACTIVE: Subsequent packet (re-arm timer)
    THREAT_ACTIVE --> IDLE_SCANNING: 3000ms Timeout Expired without packets

    state LOCKDOWN_MODE {
        COVERT_SILENCE: GPIO 2 = Strictly LOW
        TELEMETRY_FLAG: lockdown_active = true
    }

    IDLE_SCANNING --> LOCKDOWN_MODE: GPIO 0 Button Depressed (Falling Edge)
    THREAT_ACTIVE --> LOCKDOWN_MODE: GPIO 0 Button Depressed (Falling Edge)
    LOCKDOWN_MODE --> IDLE_SCANNING: GPIO 0 Button Depressed Again (Toggle)
```

---

### 3.3 Task & Inter-Process Communication (IPC) Flow

```mermaid
sequenceDiagram
    autonumber
    participant BTN as GPIO 0 (Pushbutton)
    participant ISR as gpio_0_isr_handler (IRAM)
    participant LTM as vLockdownManagerTask
    participant GAP as ble_gap_event_handler
    participant MUX as s_state_mutex
    participant STATE as g_firmguard_state
    participant LED as GPIO 2 Driver
    participant TEL as vLiveIntelligenceTelemetryTask
    participant UART as UART0 Serial Stream

    Note over GAP,STATE: Normal Detection Flow
    GAP->>MUX: xSemaphoreTake(MUTEX_TIMEOUT_MS)
    GAP->>STATE: Update scanned_count, last_mac, last_rssi
    GAP->>STATE: Set threat_active = true
    GAP->>MUX: xSemaphoreGive()
    GAP->>LED: gpio_set_level(GPIO_NUM_2, 1)

    Note over BTN,LTM: Security Lockdown Interrupt Flow
    BTN->>ISR: Falling Edge (Pin 0 Low)
    ISR->>LTM: xSemaphoreGiveFromISR(s_lockdown_sem)
    Note over ISR: Execution time < 5us
    LTM->>LTM: vTaskDelay(250ms Debounce)
    LTM->>MUX: xSemaphoreTake(MUTEX_TIMEOUT_MS)
    LTM->>STATE: Toggle lockdown_active (true)
    LTM->>MUX: xSemaphoreGive()
    LTM->>LED: gpio_set_level(GPIO_NUM_2, 0) [Forced Off]

    Note over TEL,UART: 1000ms Periodic Telemetry
    TEL->>TEL: vTaskDelayUntil(1000ms)
    TEL->>MUX: xSemaphoreTake(MUTEX_TIMEOUT_MS)
    TEL->>STATE: Atomic snapshot copy
    TEL->>MUX: xSemaphoreGive()
    TEL->>UART: Emit Minified JSON (RFC 8259)
```

---

## 4. Software Architecture Specifications

### 4.1 Apache NimBLE BLE Configuration
- **Operating Modes**: Observer / Central
- **Channel Map**: Channels 37, 38, 39
- **Scan Window**: 160 units (100 ms)
- **Scan Interval**: 160 units (100 ms)
- **Duty Cycle**: 100% continuous coverage
- **Duplicate Filter**: Disabled (`filter_duplicates = 0`) to provide live proximity monitoring of stationary and mobile trackers.

### 4.2 Telemetry Payload Specification
The telemetry engine outputs minified JSON once every 1000ms. Schema definition:

| JSON Key | Type | Description |
|:---|:---|:---|
| `uptime_ms` | `uint64` | System runtime in milliseconds since boot |
| `scanned_count` | `uint32` | Total advertising packets detected |
| `threat_count` | `uint32` | Total packets meeting or exceeding -75 dBm threshold |
| `threat_active` | `boolean` | `true` if target currently within proximity hold window |
| `lockdown_active`| `boolean` | `true` if operator emergency lockdown override is engaged |
| `last_mac` | `string` | Colon-separated hex representation of last advertiser |
| `last_rssi` | `integer` | Signal strength in dBm of last advertisement |
| `free_heap` | `uint32` | Instantaneous remaining internal SRAM in bytes |

---

## 5. Build, Flash, and Verification Instructions

### 5.1 Prerequisites
- **Framework**: ESP-IDF v5.5 (or v5.x compatible toolchain)
- **Python**: Python 3.10+
- **Serial Drivers**: CP210x or CH34x USB VCP driver installed

### 5.2 Project Build Procedure

Open an ESP-IDF terminal in the project directory:

```bash
# 1. Set the target chip architecture to ESP32
idf.py set-target esp32

# 2. Compile the firmware binary and link components
idf.py build
```

### 5.3 Device Flashing Procedure

Connect the ESP32 board to the host PC via USB:

```bash
# Flash the firmware at 460800 baud (replace COM3 with your port, e.g. /dev/ttyUSB0 on Linux)
idf.py -p COM3 -b 460800 flash
```

### 5.4 Serial Monitoring & Telemetry Inspection

Launch the ESP-IDF serial monitor:

```bash
idf.py -p COM3 monitor
```

To exit the monitor, use the shortcut: `Ctrl + ]`.

### 5.5 Unit Test Execution

To compile and execute the automated Unity test suite:

```bash
# Build unit test runner
idf.py -T test build

# Flash unit test runner to target hardware
idf.py -T test -p COM3 flash monitor
```
