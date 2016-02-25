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

#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "qos_trust_port_vty.h"
#include "qos_utils.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_trust_port_cli);

extern struct ovsdb_idl *idl;

static struct ovsrec_port *port_row_for_name(const char * port_name) {
    const struct ovsrec_port *port_row;
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        if (strcmp(port_row->name, port_name) == 0) {
            return (struct ovsrec_port *) port_row;
        }
    }

    return NULL;
}

static bool is_member_of_lag(const char *port_name) {
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

static int qos_trust_port_command(const char *port_name,
        const char *qos_trust_name) {
    if (port_name == NULL) {
        vty_out(vty, "port_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if (qos_trust_name == NULL) {
        vty_out(vty, "qos trust name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    if (is_member_of_lag(port_name)) {
        vty_out(vty, "QoS Trust cannot be configured on a member of a LAG.%s",
                VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_SUCCESS;
    }

    struct ovsrec_port *port_row = port_row_for_name(port_name);
    if (port_row == NULL) {
        vty_out(vty, "Port row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_SUCCESS;
    }

    struct smap smap;
    smap_clone(&smap, &port_row->qos_config);
    smap_replace(&smap, QOS_TRUST_KEY, qos_trust_name);
    ovsrec_port_set_qos_config(port_row, &smap);
    smap_destroy(&smap);

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_trust_port,
        qos_trust_port_cmd,
        "qos trust (none|cos|dscp)",
        "Configure QoS\n"
        "Set the QoS Trust Mode configuration for the port\n"
        "Do not trust any priority fields, and remark all of them to 0\n"
        "Trust 802.1p priority and preserve DSCP or IP-ToS\n"
        "Trust DSCP and remark the 802.1p priority to match\n") {
    const char *port_name = (char*) vty->index;
    const char *qos_trust_name = argv[0];

    return qos_trust_port_command(port_name, qos_trust_name);
}

static int qos_trust_port_no_command(const char *port_name) {
    if (port_name == NULL) {
        vty_out(vty, "port_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    if (is_member_of_lag(port_name)) {
        vty_out(vty, "QoS Trust cannot be configured on a member of a LAG.%s",
                VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_SUCCESS;
    }

    struct ovsrec_port *port_row = port_row_for_name(port_name);
    if (port_row == NULL) {
        vty_out(vty, "Port row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_SUCCESS;
    }

    struct smap smap;
    smap_clone(&smap, &port_row->qos_config);
    smap_remove(&smap, QOS_TRUST_KEY);
    ovsrec_port_set_qos_config(port_row, &smap);
    smap_destroy(&smap);

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_trust_port_no,
        qos_trust_port_no_cmd,
        "no qos trust {none|cos|dscp}",
        NO_STR
        "Configure QoS\n"
        "Remove the QoS Trust Mode configuration for the port\n"
        "Do not trust any priority fields, and remark all of them to 0\n"
        "Trust 802.1p priority and preserve DSCP or IP-ToS\n"
        "Trust DSCP and remark the 802.1p priority to match\n") {
    const char *port_name = (char*) vty->index;

    return qos_trust_port_no_command(port_name);
}

void qos_trust_port_show_running_config(const struct ovsrec_port *port_row,
        bool *header_printed, const char *header) {
    if (port_row == NULL) {
        return;
    }

    if (is_member_of_lag(port_row->name)) {
        return;
    }

    const char *qos_trust_name = smap_get(&port_row->qos_config,
            QOS_TRUST_KEY);
    if (qos_trust_name == NULL) {
        return;
    }

    if (!*header_printed) {
        *header_printed = true;
        vty_out(vty, "%s %s%s", header, port_row->name, VTY_NEWLINE);
    }
    vty_out(vty, "    qos trust %s%s", qos_trust_name, VTY_NEWLINE);
}

void qos_trust_port_show(const struct ovsrec_port *port_row) {
    if (port_row == NULL) {
        return;
    }

    if (is_member_of_lag(port_row->name)) {
        return;
    }

    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    const char *qos_trust_name = smap_get(
            &system_row->qos_config, QOS_TRUST_KEY);

    const char *map_value = smap_get(&port_row->qos_config, QOS_TRUST_KEY);
    if (map_value != NULL) {
        qos_trust_name = map_value;
    }

    vty_out(vty, " qos trust %s%s", qos_trust_name, VTY_NEWLINE);
}

void qos_trust_port_vty_init(void) {
    install_element(INTERFACE_NODE, &qos_trust_port_cmd);
    install_element(INTERFACE_NODE, &qos_trust_port_no_cmd);

    install_element(LINK_AGGREGATION_NODE, &qos_trust_port_cmd);
    install_element(LINK_AGGREGATION_NODE, &qos_trust_port_no_cmd);
}

void qos_trust_port_ovsdb_init(void) {
    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_qos_config);
}
