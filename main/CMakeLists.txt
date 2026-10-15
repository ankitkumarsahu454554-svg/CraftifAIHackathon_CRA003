# main/CMakeLists.txt - Component registration for FirmGuard-BLE
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash bt driver esp_driver_gpio esp_timer esp_system freertos log
)
