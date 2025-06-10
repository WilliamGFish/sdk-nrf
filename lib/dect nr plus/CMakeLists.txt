# CMakeLists.txt

cmake_minimum_required(VERSION 3.20.0)

# Specify your application source files
# Removed src/dect_phy_mock.c
target_sources(app PRIVATE
    src/dect_bcc.c
    src/dect_channel_mgr.c
    src/dect_config.c
    src/dect_crc.c
    src/dect_crypto.c
    src/dect_cvg.c
    src/dect_dlc.c
    src/dect_mac.c
    src/dect_power_mgr.c
    src/dect_routing.c
    src/dect_security.c
    src/dect_stats.c
)

# Specify include directories for your driver headers
target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link to nRF Connect SDK libraries for the modem and DECT PHY
# This will pull in the actual nRF modem DECT PHY driver implementation
zephyr_library_link_libraries(app
    zephyr_nrf_modem_lib # Core nRF modem library
    zephyr_drivers       # Generic drivers (might be needed for various peripherals)
    # If using mbed TLS for crypto, ensure it's linked
    # zephyr_mbedtls
    # zephyr_crypto
    # zephyr_random
)
