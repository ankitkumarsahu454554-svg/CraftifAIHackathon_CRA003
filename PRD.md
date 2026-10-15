# Product Requirements Document (PRD)

## Project Name: FirmGuard-BLE
**Firmware Version**: v1.0.0  
**Target Hardware**: ESP32-WROOM-32 / ESP32-DevKitC v4  
**Target RTOS & Framework**: ESP-IDF v5.5 (FreeRTOS 1000 Hz, Apache NimBLE)  
**Document Status**: APPROVED  

---

## 1. Executive Summary
FirmGuard-BLE is an embedded security monitoring and counter-surveillance firmware designed for the Espressif ESP32 platform. Operating continuously in high-density radio frequency environments, FirmGuard-BLE performs real-time detection, tracking, and telemetry of nearby Bluetooth Low Energy (BLE) advertisements. It provides instantaneous visual alerting via onboard GPIO actuation, offers a physical emergency lockdown switch backed by hardware interrupt service routines (ISR), and streams machine-readable JSON telemetry records over UART0 at a deterministic 1 Hz cadence.

---

## 2. System Architecture & Context
The system bridges radio-frequency edge intelligence, embedded hardware actuation, and serial telemetry:
- **Radio Core**: High-efficiency BLE Active/Passive Scanning engine utilizing the Apache NimBLE stack.
- **Actuation Core**: Hardware-driven GPIO output controlling security status indicators.
- **Fail-Safe Core**: Low-latency edge-triggered GPIO interrupt for operator lockdown override.
- **Telemetry Core**: Deterministic FreeRTOS background task providing structured intelligence reporting over primary UART.

---

## 3. Requirements Specification

### 3.1 Explicit Requirements

#### **REQ-01: Continuous BLE Advertisement Scanning & Threat Assessment**
- **Type**: Functional / Explicit
- **Description**: The system shall initialize the Apache NimBLE stack and perform continuous passive or active BLE GAP scanning across primary advertising channels (Channels 37, 38, and 39).
- **Scan Parameters**:
  - Scan Interval: 160 units (100 ms)
  - Scan Window: 160 units (100 ms, 100% duty cycle)
  - Scan Filter Policy: Accept all non-blacklisted advertising packets
- **Processing Logic**: For every discovered packet:
  - Extract advertiser MAC address and address type (public/random).
  - Extract Received Signal Strength Indicator (RSSI).
  - Evaluate threat condition: An RSSI value greater than or equal to -75 dBm indicates physical proximity of an active tracker/beacon.
- **Acceptance Criteria**: The system must process incoming advertisements without dropping frames under a load of up to 50 advertisements/second and update internal tracking metrics.

#### **REQ-02: Visual Alarm & Edge Actuation via GPIO 2**
- **Type**: Functional / Explicit
- **Description**: The system shall control a visual threat indicator mapped to GPIO 2 (onboard blue LED on ESP32 development platforms).
- **Operational Rules**:
  - When a target BLE device is detected within proximity threshold (RSSI >= -75 dBm) and lockdown mode is inactive, GPIO 2 shall be driven HIGH.
  - When no target BLE device has been detected within a sliding expiry window of 3000 ms, GPIO 2 shall be driven LOW.
  - In Lockdown Mode (see REQ-03), GPIO 2 shall remain strictly forced LOW to prevent covert visual signature emissions.
- **Acceptance Criteria**: The propagation latency from packet reception in the BLE GAP callback to GPIO 2 voltage transition shall not exceed 10 ms.

#### **REQ-03: Security Lockdown Override via GPIO 0 ISR**
- **Type**: Functional / Explicit
- **Description**: The system shall monitor GPIO 0 (active-low BOOT pushbutton) configured with an internal pull-up resistor and attached to an asynchronous, edge-triggered Interrupt Service Routine (ISR).
- **Operational Rules**:
  - The ISR shall trigger on a FALLING edge (button depress).
  - The ISR shall utilize FreeRTOS queue or task notification primitives with `FromISR` semantics to signal the core control loop.
  - Upon activation, the system toggles `Lockdown Mode`.
  - In `Lockdown Mode`:
    - Visual indicators (GPIO 2) are immediately disabled and held LOW.
    - System enters silent counter-surveillance state.
    - Serial telemetry explicitly flags the `lockdown_active: true` status.
- **Acceptance Criteria**: The ISR execution duration shall be less than 5 microseconds, with no blocking calls or memory allocations inside interrupt context.

#### **REQ-04: Live Intelligence Telemetry Task over UART0**
- **Type**: Functional / Explicit
- **Description**: The system shall execute a dedicated FreeRTOS task named `vLiveIntelligenceTelemetryTask` with a deterministic execution period of 1000 ms (1 Hz frequency).
- **Payload Format**: Minified, RFC 8259-compliant JSON string emitted to stdout/UART0 at 115200 baud, 8N1:
```json
{"uptime_ms":125000,"scanned_count":48,"threat_active":true,"lockdown_active":false,"last_mac":"AA:BB:CC:DD:EE:FF","last_rssi":-68,"free_heap":245892}
```
- **Acceptance Criteria**: Telemetry task period jitter shall not exceed +/- 5 ms under normal scheduler load. The JSON output must parse error-free with standard JSON validators.

---

### 3.2 Inferred & Operational Requirements

#### **REQ-05: Non-Volatile Storage (NVS) & RF Subsystem Resilience**
- **Type**: Non-Functional / Inferred
- **Description**: The system must handle hardware subsystem failures gracefully during bootstrap and runtime.
- **Operational Rules**:
  - Flash NVS partition shall be initialized at boot. If `ESP_ERR_NVS_NO_FREE_PAGES` or `ESP_ERR_NVS_NEW_VERSION_FOUND` occurs, the partition must be automatically erased and cleanly re-initialized.
  - The NimBLE host stack must verify baseband calibration before enabling scanning.
  - Failure to start scanning must trigger a backoff and retry mechanism rather than a kernel panic.
- **Acceptance Criteria**: The device must boot and reach steady-state scanning even across unclean shutdowns or flash partition format changes.

#### **REQ-06: FreeRTOS Deterministic Concurrency & Thread Safety**
- **Type**: Non-Functional / Inferred
- **Description**: All shared state structures (tracking statistics, threat flags, lockdown registers, MAC addresses) accessed concurrently by the NimBLE host task, the GPIO ISR, and the `vLiveIntelligenceTelemetryTask` must be protected against race conditions.
- **Operational Rules**:
  - Shared state updates must be synchronized using FreeRTOS mutual exclusion primitives (`SemaphoreHandle_t` binary mutex) or atomic access primitives.
  - Mutex acquisition inside tasks must specify a bounded timeout (maximum 50 ms) to prevent deadlock.
  - Interrupt Service Routines must never attempt to acquire standard mutexes.
- **Acceptance Criteria**: Static and runtime analysis shall confirm zero race conditions, data corruptions, or priority inversions during continuous 24-hour stress tests.

---

## 4. Hardware Pinout Table

| ESP32 Pin | Function | Electrical Direction | Internal Pull | Attached Peripheral |
|:---|:---|:---|:---|:---|
| **GPIO 2** | Threat Actuation LED | Output | None | Onboard Blue LED / External Alarm Buffer |
| **GPIO 0** | Lockdown Emergency Button | Input | Pull-Up | Onboard BOOT Button / External Toggle |
| **GPIO 1** | UART0 TXD | Output | None | USB-to-UART CP2102/CH340 (Host PC) |
| **GPIO 3** | UART0 RXD | Input | None | USB-to-UART CP2102/CH340 (Host PC) |

---

## 5. Performance Targets & Environmental Constraints
- **RAM Budget**: Peak internal SRAM consumption < 64 KB (out of 520 KB available).
- **Flash Budget**: Binary image size < 1.2 MB (fits comfortably in standard 4 MB flash).
- **Core Allocation**:
  - Core 0: Bluetooth Low Energy baseband controller and NimBLE Host Task.
  - Core 1: Application logic, GPIO handlers, and `vLiveIntelligenceTelemetryTask`.
- **System Tick Rate**: 1000 Hz (`portTICK_PERIOD_MS = 1 ms`).
