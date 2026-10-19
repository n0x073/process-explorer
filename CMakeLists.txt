# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Process Exp contributors

cmake_minimum_required(VERSION 3.20)
project(process-exp VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets DBus)

add_executable(process-exp
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
target_link_libraries(process-exp PRIVATE Qt6::Widgets Qt6::DBus)
target_compile_options(process-exp PRIVATE -Wall -Wextra -Wno-unused-parameter)

target_compile_definitions(process-exp PRIVATE PROCESS_EXP_VERSION="${PROJECT_VERSION}")

install(TARGETS process-exp RUNTIME DESTINATION bin)
install(FILES process-exp.desktop DESTINATION share/applications)
install(FILES LICENSE DESTINATION share/licenses/process-exp)
