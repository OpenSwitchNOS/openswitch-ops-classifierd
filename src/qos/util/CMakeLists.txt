# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

cmake_minimum_required (VERSION 2.8)

set (QOS qos-util)
project (${QOS})

MESSAGE("got to ${QOS}")
# Define compile flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror")

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)

include_directories(
   ${PROJECT_BINARY_DIR}
   ${PROJECT_SOURCE_DIR}
   ${INCL_DIR}/switchd
   ${OVSCOMMON_INCLUDE_DIRS}
)

MESSAGE("PROJECT_BINARY_DIR ${PROJECT_BINARY_DIR}")
MESSAGE("PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}")
MESSAGE("OVSCOMMON_INCLUDE_DIRS ${OVSCOMMON_INCLUDE_DIRS}")

# Sources to build qos
file(GLOB SOURCES
   "qos_*.c"
)

add_library(${QOS} SHARED ${SOURCES})
install(TARGETS ${QOS} LIBRARY DESTINATION lib)

MESSAGE("done with ${QOS}")
