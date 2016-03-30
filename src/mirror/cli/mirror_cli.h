/****************************************************************************
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

#ifndef _MIRROR_CLI_H_
#define _MIRROR_CLI_H_

#define MAX_MIRROR_SESSION_NAME_LEN 64
#define MIRROR_STR           "mirror"
#define MIRROR_SESSION_STR   "mirror_session"
#define MIRROR_SESSION_NAME_STR "mirror_session_name"
#define DST_STR              "destination"
#define IFACE_STR            "interface"
#define IFACE_NAME_STR       "interface_name"
#define SRC_STR              "source"
#define SRC_DIR_TX           "tx"
#define SRC_DIR_RX           "rx"
#define SRC_DIR_BOTH         "both"
#define SHUT_STR             "shutdown"

vtysh_ret_val cli_show_mirror_running_config_callback(void*);
void mirror_pre_init(void);
void mirror_vty_init(void);

#endif /* _MIRROR_CLI_H_ */
