cmake_minimum_required(VERSION 3.1.0)

project(packet_sniffer VERSION 1.0.0 LANGUAGES CXX)

# Enable compile commands export
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Set UI files directory
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/ui)

# Add cmake modules path
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Qt5 COMPONENTS Widgets Network REQUIRED)
find_package(PCAP REQUIRED)

# Define UI files
set(UI_FILES
    ui/mainwindow.ui
)

set(SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/portscanner.cpp
    src/packetcapture.cpp
)

set(HEADERS
    include/mainwindow.h
    include/portscanner.h
    include/packetcapture.h
)

add_executable(${PROJECT_NAME} 
    ${SOURCES}
    ${HEADERS}
    ${UI_FILES}
)

target_include_directories(${PROJECT_NAME} 
    PRIVATE 
    include
    ${CMAKE_CURRENT_BINARY_DIR}  # Add this for ui_mainwindow.h
    ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
    Qt5::Widgets
    Qt5::Network
    ${PCAP_LIBRARIES}
)

# Add command to copy compile_commands.json to root directory
add_custom_target(
    copy-compile-commands ALL
    ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_BINARY_DIR}/compile_commands.json
    ${CMAKE_SOURCE_DIR}/compile_commands.json
    DEPENDS ${CMAKE_BINARY_DIR}/compile_commands.json
)