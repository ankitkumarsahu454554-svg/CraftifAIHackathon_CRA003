# test/CMakeLists.txt - Unit test component registration for FirmGuard-BLE
idf_component_register(
    SRCS "test_ble_tracker.c"
    INCLUDE_DIRS "." "../main"
    REQUIRES unity driver esp_driver_gpio esp_timer freertos main nvs_flash
)
