cmake_minimum_required(VERSION 3.20)
project(procexp-linux VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets DBus)

add_executable(procexp
  src/main.cpp
  src/types.h
  src/procfs.h src/procfs.cpp
  src/collector.h src/collector.cpp
  src/processmodel.h src/processmodel.cpp
  src/widgets.h src/widgets.cpp
  src/sysinfodialog.h src/sysinfodialog.cpp
  src/dialogs.h src/dialogs.cpp
  src/mainwindow.h src/mainwindow.cpp
)
target_link_libraries(procexp PRIVATE Qt6::Widgets Qt6::DBus)
target_compile_options(procexp PRIVATE -Wall -Wextra -Wno-unused-parameter)

install(TARGETS procexp RUNTIME DESTINATION bin)
install(FILES procexp-linux.desktop DESTINATION share/applications)
