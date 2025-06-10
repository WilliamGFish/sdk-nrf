# CMakeLists.txt for my_dect_app

cmake_minimum_required(VERSION 3.20.0)

# Include Zephyr's standard build system files
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(my_dect_app)

# Specify your application source files
# Removed src/dect_phy_mock.c
target_sources(app PRIVATE
    src/main.c
)

