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

#include <config.h>

#include "qos_dscp_port_vty.h"

#include <libaudit.h>

#include "memory.h"
#include "openswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovsdb-idl.h"
#include "qos_trust_port_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "vswitch-idl.h"
#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_user.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_dscp_port_cli);
extern struct ovsdb_idl *idl;

/**
 * Executes the qos_dscp_port_command for the given port_name and
 * dscp_map_index.
 */
static int
qos_dscp_port_command(const char *port_name,
        const char *dscp_map_index)
{
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
        vty_out(vty, "Port %s does not exist.%s",
                port_name, VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    const char *qos_trust_name = qos_trust_port_get_value(port_row);
    if (qos_trust_name == NULL ||
            strncmp(qos_trust_name, QOS_TRUST_NONE_STRING,
                    QOS_CLI_STRING_BUFFER_SIZE) != 0) {
        vty_out(vty, "QoS DSCP override is only allowed\
 if the trust mode is 'none'.%s",
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

/**
 * Executes the qos_dscp_port_command for the given port_name and
 * dscp_map_index.
 */
DEFUN(qos_dscp_port,
        qos_dscp_port_cmd,
        "qos dscp <0-63>",
        "Configure QoS\n"
        "Set the DSCP override for the port\n"
        "The index into the DSCP Map\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    size_t ausize = sizeof(aubuf);
    strncpy(aubuf, "op=CLI: qos dscp", ausize);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *port_name = (char*) vty->index;
    qos_audit_encode(aubuf, ausize, "port_name", port_name);

    const char *dscp_map_index = argv[0];
    qos_audit_encode(aubuf, ausize, "dscp_map_index", dscp_map_index);

    int result = qos_dscp_port_command(port_name, dscp_map_index);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG,
            aubuf, hostname, NULL, NULL, result);

    return result;
}

/**
 * Executes the qos_dscp_port_no_command for the given port_name.
 */
static int
qos_dscp_port_no_command(const char *port_name)
{
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
        vty_out(vty, "Port %s does not exist.%s", port_name, VTY_NEWLINE);
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

/**
 * Executes the qos_dscp_port_no_command for the given port_name.
 */
DEFUN(qos_dscp_port_no,
        qos_dscp_port_no_cmd,
        "no qos dscp {<0-63>}",
        NO_STR
        "Configure QoS\n"
        "Remove the QoS DSCP override for the port\n"
        "The index into the DSCP Map\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    size_t ausize = sizeof(aubuf);
    strncpy(aubuf, "op=CLI: no qos dscp", ausize);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *port_name = (char*) vty->index;
    qos_audit_encode(aubuf, ausize, "port_name", port_name);

    int result = qos_dscp_port_no_command(port_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG,
            aubuf, hostname, NULL, NULL, result);

    return result;
}

/**
 * Initializes qos_dscp_port_vty.
 */
void
qos_dscp_port_vty_init(void)
{
    install_element(INTERFACE_NODE, &qos_dscp_port_cmd);
    install_element(INTERFACE_NODE, &qos_dscp_port_no_cmd);

    install_element(LINK_AGGREGATION_NODE, &qos_dscp_port_cmd);
    install_element(LINK_AGGREGATION_NODE, &qos_dscp_port_no_cmd);
}

/**
 * Initializes qos_dscp_port_ovsdb.
 */
void
qos_dscp_port_ovsdb_init(void)
{
    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_qos_config);
}
