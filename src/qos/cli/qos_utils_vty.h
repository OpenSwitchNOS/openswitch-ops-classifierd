/****************************************************************************
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 *
 ***************************************************************************/

#ifndef _QOS_UTILS_VTY_H_
#define _QOS_UTILS_VTY_H_

#include <stdbool.h>

#define QOS_INVALID_STRING_ERROR_MESSAGE \
"This field can have a length up to 64 characters.\n\
The allowed characters are alphanumeric, underscore ('_'),\n\
hyphen ('-'), and dot ('.').%s"

/**
 * Returns true if the string is a valid string.
 */
bool qos_is_valid_string(const char *string);

/**
 * Returns the port row for the given port name.
 */
struct ovsrec_port *port_row_for_name(const char *port_name);

/**
 * Returns true if the given port_name is a member of a lag.
 */
bool is_member_of_lag(const char *port_name);

#endif /* _QOS_UTILS_VTY_H_ */