cmake_minimum_required(VERSION 3.0)

project(SocketTestQt)

# Set some Win32 Specific Settings
if(WIN32)
set(GUI_TYPE WIN32)
endif(WIN32)
# Set some Apple MacOS Specific settings
if(APPLE)
set(GUI_TYPE MACOSX_BUNDLE)
endif(APPLE)

find_package(Qt5Widgets REQUIRED)
find_package(Qt5Gui     REQUIRED)
find_package(Qt5Core    REQUIRED)
find_package(Qt5Network REQUIRED)

if(NOT WIN32)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=gnu++0x")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -Wpedantic -g -O0 -std=gnu++0x")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wall -Wextra -Wpedantic -std=gnu++0x")
endif()

include_directories(${QT_INCLUDES})
include_directories(.)

# ==============================================================================
# Source
# ==============================================================================  
set(APP_SOURCE main.cpp SocketTestQ.cpp tcpportlist.cpp udpportlist.cpp csslserver.cpp)
set(UISrcs SocketTestQ.ui tcpportlist.ui udpportlist.ui)

# ==============================================================================
# Target
# ==============================================================================
add_executable(socketTestQt ${GUI_TYPE} ${APP_SOURCE} ${UISrcs} ${MOCSrcs} Image.qrc)

set_target_properties(socketTestQt PROPERTIES
                      AUTOMOC TRUE
                      AUTORCC TRUE
                      AUTOUIC TRUE)

target_link_libraries(socketTestQt Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network)

target_include_directories(socketTestQt PRIVATE
                          ${CMAKE_CURRENT_BINARY_DIR}
                          ${CMAKE_CURRENT_SOURCE_DIR}
                          ${CMAKE_SOURCE_DIR})


set_property(TARGET socketTestQt PROPERTY C_STANDARD 99)

