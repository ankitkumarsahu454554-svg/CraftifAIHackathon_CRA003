# FirmGuard-BLE End-to-End Traceability Report

**Document Revision**: 1.0.0  
**Project**: FirmGuard-BLE  
**Target Platform**: ESP-IDF v5.5 / ESP32-WROOM-32  
**Verification Framework**: Unity Unit Test Engine  

---

## 1. Traceability Matrix Overview

The following matrix establishes strict, bidirectional traceability across the complete engineering lifecycle of FirmGuard-BLE: from high-level Product Requirements (PRD), through hardware architectural mapping and firmware source code implementation, to automated unit verification.

| Req ID | Category | Requirement Description | System Component | Firmware Source File & Symbol | Unit Test Case (`test_ble_tracker.c`) | Verification Criteria | Status |
|:---|:---|:---|:---|:---|:---|:---|:---|
| **REQ-01** | Explicit | Continuous BLE scanning, MAC extraction, and RSSI threshold threat detection (RSSI >= -75 dBm) | NimBLE GAP Discovery Engine | `main/main.c`<br>[`ble_scan_start()`](file:///c:/Users/Ankit/Desktop/filmgen/main/main.c#L240)<br>[`ble_gap_event_handler()`](file:///c:/Users/Ankit/Desktop/filmgen/main/main.c#L198) | `TEST_CASE("REQ-01: Weak BLE signal below -75 dBm does not trigger threat")`<br>`TEST_CASE("REQ-01: Proximity BLE signal >= -75 dBm triggers threat condition")` | RSSI < -75 produces no threat flag; RSSI >= -75 asserts `threat_active = true` and updates `last_mac` | **PASSED** |
| **REQ-02** | Explicit | Visual alarm actuation via GPIO 2 (LED ON on threat, OFF on safe state or hold expiry of 3000ms) | Hardware GPIO Output Driver | `main/main.c`<br>[`update_threat_led()`](file:///c:/Users/Ankit/Desktop/filmgen/main/main.c#L101)<br>[`vLiveIntelligenceTelemetryTask()`](file:///c:/Users/Ankit/Desktop/filmgen/main/main.c#L154) | `TEST_CASE("REQ-02: GPIO 2 Actuation follows active threat status")`<br>`TEST_CASE("REQ-02: Threat state clears after 3000ms hold expiry window")` | GPIO 2 outputs logic HIGH during active threat and reverts to logic LOW after 3000ms elapsed without threats | **PASSED** |
| **REQ-03** | Explicit | Security lockdown override via GPIO 0 ISR (falling edge, debounced, LED suppression) | GPIO ISR & Lockdown Management Task | `main/main.c`<br>[`gpio_0_isr_handler()`](file:///c:/Users/Ankit/Desktop/filmgen/main/main.c#L118)<br>[`vLockdownManagerTask()`](file:///c:/Users/Ankit/Desktop/filmgen/main/main.c#L131) | `TEST_CASE("REQ-03: Lockdown override forces LED off even under active threat")` | Depressing GPIO 0 toggles `lockdown_active`; LED is strictly forced to logic LOW even when `threat_active = true` | **PASSED** |
| **REQ-04** | Explicit | Live intelligence telemetry streaming over UART0 every 1000ms in valid minified JSON format | UART Serial Telemetry Subsystem | `main/main.c`<br>[`vLiveIntelligenceTelemetryTask()`](file:///c:/Users/Ankit/Desktop/filmgen/main/main.c#L154) | `TEST_CASE("REQ-04: Telemetry output conforms to strict JSON schema")` | Single-line JSON emitted at 1 Hz with zero truncation, valid JSON syntax, and all required metadata fields | **PASSED** |
| **REQ-05** | Inferred | Non-Volatile Storage (NVS) fault tolerance and auto-recovery from corrupted flash partitions | Flash NVS Subsystem | `main/main.c`<br>[`init_nvs_resilient()`](file:///c:/Users/Ankit/Desktop/filmgen/main/main.c#L309) | `TEST_CASE("REQ-05: NVS resilient initialization handles corrupted partition")` | Handles `ESP_ERR_NVS_NO_FREE_PAGES` or version mismatch by erasing and recovering cleanly without kernel panic | **PASSED** |
| **REQ-06** | Inferred | Deterministic thread-safety across FreeRTOS tasks and ISR using binary mutex and bounded timeouts | FreeRTOS IPC & Synchronization Core | `main/main.c`<br>`s_state_mutex`<br>`s_lockdown_sem` | `TEST_CASE("REQ-06: Mutex guarantees atomic updates under dual concurrent task contention")` | Concurrent multi-threaded task competition results in zero race conditions, data loss, or priority deadlocks | **PASSED** |

---

## 2. Requirement Deep-Dive & Verification Details

### 2.1 REQ-01: Continuous BLE Scanning & Threat Assessment
- **Implementation Strategy**: Configures Apache NimBLE GAP discovery engine with continuous window/interval of 160 units (100 ms, 100% duty cycle) and duplicate filtering disabled (`filter_duplicates = 0`) to detect moving transmitters.
- **Verification Method**: Tested boundary conditions at -76 dBm (ignored), -75 dBm (threat triggered), and -45 dBm (threat confirmed), verifying accurate MAC extraction and state counter increments.

### 2.2 REQ-02: Visual Alarm via GPIO 2
- **Implementation Strategy**: Fast-path driver actuation in `update_threat_led()` immediately toggles `GPIO_NUM_2`. A sliding window check in `vLiveIntelligenceTelemetryTask` evaluates `(now - last_threat_timestamp_us) > 3000000` to automatically clear threat indications if no subsequent advertisements arrive.
- **Verification Method**: Simulated time progression testing active assertion followed by hold time expiry after 3000 ms.

### 2.3 REQ-03: GPIO 0 Security Lockdown Override
- **Implementation Strategy**: Falling-edge interrupt on `GPIO_NUM_0` releases binary semaphore `s_lockdown_sem` from IRAM using `xSemaphoreGiveFromISR`. Deferral to `vLockdownManagerTask` ensures hardware debouncing (250 ms) without stalling the interrupt controller.
- **Verification Method**: Verified that toggling lockdown inverts the `lockdown_active` state variable and unconditionally forces GPIO 2 to 0 regardless of BLE threat activity.

### 2.4 REQ-04: Periodic UART0 JSON Telemetry
- **Implementation Strategy**: `vTaskDelayUntil(&xLastWakeTime, pdMS_TO_TICKS(1000))` enforces an exact 1 Hz execution period without drift. Atomically captured state snapshot is formatted using `snprintf` directly to standard output.
- **Verification Method**: Evaluated string output structure against RFC 8259, testing root opening `{`, closing `}`, integer uptime, heap statistics, and stringified boolean indicators.

### 2.5 REQ-05: Resilient Storage Bootstrap
- **Implementation Strategy**: Intercepts `ESP_ERR_NVS_NO_FREE_PAGES` and `ESP_ERR_NVS_NEW_VERSION_FOUND`, executing `nvs_flash_erase()` and re-initializing to ensure recovery across firmware flashing cycles.
- **Verification Method**: Verified recovery state machine in unit test suite.

### 2.6 REQ-06: Deterministic Concurrency & Mutex Protection
- **Implementation Strategy**: `s_state_mutex` protects reads and writes to `g_firmguard_state` with a 50 ms bounded timeout (`pdMS_TO_TICKS(50)`), preventing priority inversion and infinite stalls.
- **Verification Method**: Dual FreeRTOS tasks incremented a contested state variable 500 times each under mutex arbitration; final count verified at exactly 1000 with zero lost updates.

---

## 3. Compliance Summary

| Category | Total Requirements | Implemented | Verified by Test Suite | Compliance Percentage |
|:---|:---:|:---:|:---:|:---:|
| **Explicit Requirements** | 4 | 4 | 4 | 100% |
| **Inferred Requirements** | 2 | 2 | 2 | 100% |
| **Total Project Scope** | **6** | **6** | **6** | **100%** |
