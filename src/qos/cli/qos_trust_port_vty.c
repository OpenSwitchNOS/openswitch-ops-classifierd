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
#include "qos_trust_port_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_trust_port_cli);
extern struct ovsdb_idl *idl;

/**
 * Executes the trust_port_command for the given port_name and
 * qos_trust_name.
 */
static int
qos_trust_port_command(const char *port_name,
        const char *qos_trust_name)
{
    if (port_name == NULL) {
        vty_out(vty, "port_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (qos_trust_name == NULL) {
        vty_out(vty, "qos trust name cannot be NULL.%s", VTY_NEWLINE);
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
        vty_out(vty, "QoS Trust cannot be configured on a member of a LAG.%s",
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

/**
 * Executes the trust_port_command.
 */
DEFUN(qos_trust_port,
        qos_trust_port_cmd,
        "qos trust (none|cos|dscp)",
        "Configure QoS\n"
        "Set the QoS Trust Mode configuration for the port\n"
        "Do not trust any priority fields, and remark all of them to 0\n"
        "Trust 802.1p priority and preserve DSCP or IP-ToS\n"
        "Trust DSCP and remark the 802.1p priority to match\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: qos trust", sizeof(aubuf));
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *port_name = (char*) vty->index;
    if (port_name != NULL) {
        char *cfg = audit_encode_nv_string("port_name", port_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }

    const char *qos_trust_name = argv[0];
    if (qos_trust_name != NULL) {
        char *cfg = audit_encode_nv_string("qos_trust_name",
                qos_trust_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }

    int result = qos_trust_port_command(port_name, qos_trust_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG,
            aubuf, hostname, NULL, NULL, result);

    return result;
}

/**
 * Executes the trust_port_no_command for the given port_name.
 */
static int
qos_trust_port_no_command(const char *port_name)
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
        vty_out(vty, "QoS Trust cannot be configured on a member of a LAG.%s",
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

/**
 * Executes the trust_port_no_command.
 */
DEFUN(qos_trust_port_no,
        qos_trust_port_no_cmd,
        "no qos trust {none|cos|dscp}",
        NO_STR
        "Configure QoS\n"
        "Remove the QoS Trust Mode configuration for the port\n"
        "Do not trust any priority fields, and remark all of them to 0\n"
        "Trust 802.1p priority and preserve DSCP or IP-ToS\n"
        "Trust DSCP and remark the 802.1p priority to match\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: no qos trust", sizeof(aubuf));
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *port_name = (char*) vty->index;
    if (port_name != NULL) {
        char *cfg = audit_encode_nv_string("port_name", port_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }

    int result = qos_trust_port_no_command(port_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG,
            aubuf, hostname, NULL, NULL, result);

    return result;
}

/**
 * Executes the trust_port_show command for the given port_row.
 */
void
qos_trust_port_show(const struct ovsrec_port *port_row)
{
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

/**
 * Initializes qos_trust_port_vty.
 */
void
qos_trust_port_vty_init(void)
{
    install_element(INTERFACE_NODE, &qos_trust_port_cmd);
    install_element(INTERFACE_NODE, &qos_trust_port_no_cmd);

    install_element(LINK_AGGREGATION_NODE, &qos_trust_port_cmd);
    install_element(LINK_AGGREGATION_NODE, &qos_trust_port_no_cmd);
}

/**
 * Initializes qos_trust_port_ovsdb.
 */
void
qos_trust_port_ovsdb_init(void)
{
    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_qos_config);
}
