cmake_minimum_required(VERSION 3.10)
project(NetworkTrafficAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(SQLite3 REQUIRED)
find_package(CURL REQUIRED)

# Find jsoncpp using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)
link_directories(${JSONCPP_LIBRARY_DIRS})

# Find libpcap
find_library(PCAP_LIBRARY pcap)
find_path(PCAP_INCLUDE_DIR pcap.h)

if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR "libpcap not found")
endif()

# Add executable for traffic analyzer
add_executable(traffic_analyzer 
    src/main.cpp
    src/traffic_analyzer.cpp
)

# Add executable for CLI
add_executable(traffic_analyzer_cli
    src/traffic_analyzer_ui.cpp
    src/traffic_analyzer_cli.cpp
)

# Link libraries for traffic analyzer
target_link_libraries(traffic_analyzer 
    PRIVATE 
    ${SQLite3_LIBRARIES}
    ${PCAP_LIBRARY}
    ${CURL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
)

# Link libraries for CLI
target_link_libraries(traffic_analyzer_cli
    PRIVATE
    ${SQLite3_LIBRARIES}
    ${CURL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
)

# Include directories for traffic analyzer
target_include_directories(traffic_analyzer
    PRIVATE
    ${SQLite3_INCLUDE_DIRS}
    ${PCAP_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
    ${JSONCPP_INCLUDE_DIRS}
    include
)

# Include directories for CLI
target_include_directories(traffic_analyzer_cli
    PRIVATE
    ${SQLite3_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${JSONCPP_INCLUDE_DIRS}
    include
) 