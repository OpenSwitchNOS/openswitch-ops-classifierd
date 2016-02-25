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
#include "qos_dscp_port_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_dscp_port_cli);
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

static int qos_dscp_port_command(const char *port_name,
        const char *dscp_map_index) {
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
        vty_out(vty, "QoS DSCP cannot be configured on a member of a LAG.%s",
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

    const char *qos_trust_name = smap_get(&port_row->qos_config,
            QOS_TRUST_KEY);
    if (qos_trust_name == NULL || strcmp(qos_trust_name,
            QOS_TRUST_NONE_STRING) != 0) {
        vty_out(vty, "QoS DSCP override is only allowed if the port trust mode is 'none'.%s",
                VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_SUCCESS;
    }

    struct smap smap;
    smap_clone(&smap, &port_row->qos_config);
    smap_replace(&smap, QOS_DSCP_OVERRIDE_KEY, dscp_map_index);
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

DEFUN (qos_dscp_port,
        qos_dscp_port_cmd,
        "qos dscp <0-63>",
        "Configure QoS\n"
        "Set the DSCP override for the port\n"
        "The index into the DSCP Map\n") {
    const char *port_name = (char*) vty->index;
    const char *dscp_map_index = argv[0];

    return qos_dscp_port_command(port_name, dscp_map_index);
}

static int qos_dscp_port_no_command(const char *port_name) {
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
        vty_out(vty, "QoS DSCP cannot be configured on a member of a LAG.%s",
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
    smap_remove(&smap, QOS_DSCP_OVERRIDE_KEY);
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

DEFUN (qos_dscp_port_no,
        qos_dscp_port_no_cmd,
        "no qos dscp {<0-63>}",
        NO_STR
        "Configure QoS\n"
        "Remove the QoS DSCP override for the port\n"
        "The index into the DSCP Map\n") {
    const char *port_name = (char*) vty->index;

    return qos_dscp_port_no_command(port_name);
}

void qos_dscp_port_vty_init(void) {
    install_element(INTERFACE_NODE, &qos_dscp_port_cmd);
    install_element(INTERFACE_NODE, &qos_dscp_port_no_cmd);

    install_element(LINK_AGGREGATION_NODE, &qos_dscp_port_cmd);
    install_element(LINK_AGGREGATION_NODE, &qos_dscp_port_no_cmd);
}

void qos_dscp_port_ovsdb_init(void) {
    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_qos_config);
}
