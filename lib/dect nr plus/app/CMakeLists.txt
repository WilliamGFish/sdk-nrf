cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(my_dect_app)

# Include the DECT NR+ module (its path is relative to the workspace root)
# Note: If your module is in modules/lib/dect_nr_plus,
# it will be automatically found by Zephyr's module discovery.
# Explicitly listing it here is often not needed if placed in a standard path.
# list(APPEND EXTRA_MODULES "${CMAKE_CURRENT_SOURCE_DIR}/../../modules/lib/dect_nr_plus")

target_sources(app PRIVATE src/main.c)

# Link to the DECT NR+ library. The name usually matches the zephyr_library() call in its CMakeLists.txt.
# The build system automatically resolves include paths for PUBLIC headers of linked libraries.
target_link_libraries(app PRIVATE dect_nr_plus) # This is the key!

# Link to other Zephyr libraries your app might use directly
target_link_libraries(app PRIVATE logging settings net)