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

#include <libaudit.h>

#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "qos_utils_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_utils_cli);
extern struct ovsdb_idl *idl;

static bool is_valid_char(char c) {
    return isalnum(c) || c == '_' || c == '-';
}

bool qos_is_valid_string(const char *string) {
    if (string == NULL) {
        return false;
    }

    int length = strlen(string);
    if (length > QOS_CLI_MAX_STRING_LENGTH) {
        return false;
    }

    int i;
    for (i = 0; i < length; i++) {
        char c = string[i];

        if (!is_valid_char(c)) {
            return false;
        }
    }

    return true;
}

struct ovsrec_port *port_row_for_name(const char *port_name) {
    const struct ovsrec_port *port_row;
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        if (strcmp(port_row->name, port_name) == 0) {
            return (struct ovsrec_port *) port_row;
        }
    }

    return NULL;
}

bool is_member_of_lag(const char *port_name) {
    const struct ovsrec_port *port_row;
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        int i;
        for (i = 0; i < port_row->n_interfaces; i++) {
            if ((strcmp(port_row->interfaces[i]->name, port_name) == 0)
                    && (strcmp(port_row->name, port_name) != 0)) {
                return true;
            }
        }
    }

    return false;
}
