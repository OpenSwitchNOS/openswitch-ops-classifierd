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

static int qos_dscp_port_command(const char *port_name,
        const char *dscp_map_index) {
    if (port_name == NULL) {
        vty_out(vty, "port_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
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
        return CMD_OVSDB_FAILURE;
    }

    struct ovsrec_port *port_row = port_row_for_name(port_name);
    if (port_row == NULL) {
        vty_out(vty, "Port row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    const char *qos_trust_name = smap_get(&port_row->qos_config,
            QOS_TRUST_KEY);
    if (qos_trust_name == NULL || strcmp(qos_trust_name,
            QOS_TRUST_NONE_STRING) != 0) {
        vty_out(vty, "QoS DSCP override is only allowed if the port trust mode is 'none'.%s",
                VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
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
    char aubuf[160];
    strcpy(aubuf, "op=CLI: qos dscp");
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *port_name = (char*) vty->index;
    if (port_name != NULL) {
        char *cfg = audit_encode_nv_string("port_name", port_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, 130);
            free(cfg);
        }
    }

    const char *dscp_map_index = argv[0];
    if (dscp_map_index != NULL) {
        char *cfg = audit_encode_nv_string("dscp_map_index", dscp_map_index, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, 130);
            free(cfg);
        }
    }

    int result = qos_dscp_port_command(port_name, dscp_map_index);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static int qos_dscp_port_no_command(const char *port_name) {
    if (port_name == NULL) {
        vty_out(vty, "port_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
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
        return CMD_OVSDB_FAILURE;
    }

    struct ovsrec_port *port_row = port_row_for_name(port_name);
    if (port_row == NULL) {
        vty_out(vty, "Port row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
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
    char aubuf[160];
    strcpy(aubuf, "op=CLI: no qos dscp");
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *port_name = (char*) vty->index;
    if (port_name != NULL) {
        char *cfg = audit_encode_nv_string("port_name", port_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, 130);
            free(cfg);
        }
    }

    int result = qos_dscp_port_no_command(port_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
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
