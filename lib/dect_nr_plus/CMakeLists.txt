# modules/lib/dect_nr_plus/CMakeLists.txt
zephyr_library() # Declares this as a Zephyr library/module

# List all source files in the module
zephyr_library_sources(
    src/dect_bcc.c
    src/dect_channel_mgr.c
    src/dect_config.c
    src/dect_crc.c
    src/dect_crypto.c
    src/dect_cvg.c
    src/dect_dlc.c
    src/dect_mac.c
    src/dect_nr_plus_subsystem.c
    src/dect_phy_nrf9161.c
    src/dect_power_mgr.c
    src/dect_routing.c
    src/dect_security.c
    src/dect_stats.c
)

# Specify public include directories.
# Headers here will be available to other modules/applications via their path relative to 'include'.
# E.g., #include <dect_nr_plus/dect_mac.h>
target_include_directories(${ZEPHYR_LIBRARY_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include/dect_nr_plus
)

# Specify private include directories (for headers used only within this module)
target_include_directories(${ZEPHYR_LIBRARY_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include # For headers like nrf_modem_dect_phy.h if copied here (though generally not recommended)
)

# Explicitly declare dependencies for this module.
# These are usually implicitly handled by Kconfig dependencies, but can be good for clarity.
# This module will depend on net_l2, nrf_modem_dect_phy, mbedtls, entropy, etc.
# target_link_libraries(${ZEPHYR_LIBRARY_NAME} PRIVATE net_l2 nrf_modem_lib mbedtls entropy settings crc)

