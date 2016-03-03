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
#include "qos_trust_global_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_trust_global_cli);
extern struct ovsdb_idl *idl;

static int qos_trust_global_command(const char *qos_trust_name) {
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

    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    if (system_row == NULL) {
        vty_out(vty, "System row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    struct smap smap;
    smap_clone(&smap, &system_row->qos_config);
    smap_replace(&smap, QOS_TRUST_KEY, qos_trust_name);
    ovsrec_system_set_qos_config(system_row, &smap);
    smap_destroy(&smap);

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_trust_global,
        qos_trust_global_cmd,
        "qos trust (none|cos|dscp)",
        "Configure QoS\n"
        "Set the top-level QoS Trust Mode configuration\n"
        "Do not trust any priority fields, and remark all of them to 0\n"
        "Trust 802.1p priority and preserve DSCP or IP-ToS\n"
        "Trust DSCP and remark the 802.1p priority to match\n") {
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: qos trust", QOS_CLI_AUDIT_BUFFER_SIZE);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *qos_trust_name = argv[0];
    if (qos_trust_name != NULL) {
        char *cfg = audit_encode_nv_string("qos_trust_name", qos_trust_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }

    int result = qos_trust_global_command(qos_trust_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static int qos_trust_global_no_command(void) {
    qos_trust_global_command(QOS_TRUST_DEFAULT);

    return CMD_SUCCESS;
}

DEFUN (qos_trust_global_no,
        qos_trust_global_no_cmd,
        "no qos trust {none|cos|dscp}",
        NO_STR
        "Configure QoS\n"
        "Restore the top-level QoS Trust Mode to its factory default\n"
        "Do not trust any priority fields, and remark all of them to 0\n"
        "Trust 802.1p priority and preserve DSCP or IP-ToS\n"
        "Trust DSCP and remark the 802.1p priority to match\n") {
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: no qos trust", QOS_CLI_AUDIT_BUFFER_SIZE);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    int result = qos_trust_global_no_command();

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static int qos_trust_global_show_command(const char *default_parameter) {
    const char *qos_trust_name;
    if (default_parameter != NULL) {
        /* Show the factory default. */
        qos_trust_name = QOS_TRUST_DEFAULT;
    } else {
        /* Show the active value. */
        const struct ovsrec_system *system_row = ovsrec_system_first(idl);
        if (system_row == NULL) {
            vty_out(vty, "system row cannot be NULL.%s", VTY_NEWLINE);
            return CMD_OVSDB_FAILURE;
        }

        qos_trust_name = smap_get(&system_row->qos_config, QOS_TRUST_KEY);
    }

    vty_out(vty, "qos trust %s%s", qos_trust_name, VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (qos_trust_global_show,
        qos_trust_global_show_cmd,
        "show qos trust {default}",
        SHOW_STR
        "Show QoS Configuration\n"
        "Show QoS Trust Configuration\n"
        "Display the factory default value\n") {
    const char *default_parameter = argv[0];

    return qos_trust_global_show_command(default_parameter);
}

static vtysh_ret_val qos_trust_global_show_running_config_callback(
        void *p_private) {
    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    if (system_row == NULL) {
        return e_vtysh_ok;
    }

    const char *qos_trust_name = smap_get(&system_row->qos_config,
            QOS_TRUST_KEY);
    if (qos_trust_name == NULL) {
        return e_vtysh_ok;
    }

    if (strncmp(qos_trust_name, QOS_TRUST_DEFAULT, QOS_CLI_MAX_STRING_LENGTH) != 0) {
        vty_out(vty, "qos trust %s%s", qos_trust_name, VTY_NEWLINE);
    }

    return e_vtysh_ok;
}

void qos_trust_global_show_running_config(void) {
    vtysh_context_client client;
    memset(&client, 0, sizeof(vtysh_context_client));
    client.p_client_name = "qos_trust_global_show_running_config_callback";
    client.client_id = e_vtysh_config_context_qos_trust;
    client.p_callback = &qos_trust_global_show_running_config_callback;

    vtysh_ret_val retval = vtysh_context_addclient(
            e_vtysh_config_context, e_vtysh_config_context_qos_trust, &client);
    if(retval != e_vtysh_ok) {
        vty_out(vty, "Unable to add client callback.%s", VTY_NEWLINE);
    }
}

void qos_trust_global_vty_init(void) {
    install_element(CONFIG_NODE, &qos_trust_global_cmd);
    install_element(CONFIG_NODE, &qos_trust_global_no_cmd);
    install_element (ENABLE_NODE, &qos_trust_global_show_cmd);
}

void qos_trust_global_ovsdb_init(void) {
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_qos_config);
}
