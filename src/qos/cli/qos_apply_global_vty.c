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
#include "qos_apply_global_vty.h"
#include "qos_queue_profile_vty.h"
#include "qos_schedule_profile_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_apply_global_cli);
extern struct ovsdb_idl *idl;

bool qos_profiles_contain_same_queues(
        struct ovsrec_q_profile * queue_profile_row,
        struct ovsrec_qos *schedule_profile_row) {
    /* Check that each queue profile queue_num is in the schedule profile. */
    int i;
    for (i = 0; i < queue_profile_row->n_q_profile_entries; i++) {
        int64_t queue_num = queue_profile_row->key_q_profile_entries[i];
        if (!qos_schedule_profile_has_queue_num(schedule_profile_row, queue_num)) {
            return false;
        }
    }

    /* Check that each schedule profile queue_num is in the queue profile. */
    for (i = 0; i < schedule_profile_row->n_queues; i++) {
        int64_t queue_num = schedule_profile_row->key_queues[i];
        if (!qos_queue_profile_has_queue_num(queue_profile_row, queue_num)) {
            return false;
        }
    }

    return true;
}

static int qos_apply_global_command(const char *queue_profile_name,
        const char *schedule_profile_name) {
    if (queue_profile_name == NULL) {
        vty_out(vty, "queue_profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if (!qos_is_valid_string(queue_profile_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if (schedule_profile_name == NULL) {
        vty_out(vty, "schedule_profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if (!qos_is_valid_string(schedule_profile_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Retrieve the queue profile. */
    struct ovsrec_q_profile *queue_profile_row = qos_get_queue_profile_row(
            queue_profile_name);
    if (queue_profile_row == NULL) {
        vty_out(vty, "queue_profile_row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Check that the profile is complete. */
    if (!qos_queue_profile_is_complete(queue_profile_row)) {
        vty_out(vty, "queue_profile_row cannot be incomplete.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* If the profile is strict, make sure the 'strict' profile exists. */
    if (strcmp(schedule_profile_name, OVSREC_QUEUE_ALGORITHM_STRICT) == 0) {
        qos_schedule_profile_create_strict_profile(txn);
    }

    /* Retrieve the schedule profile. */
    struct ovsrec_qos *schedule_profile_row = qos_get_schedule_profile_row(
            schedule_profile_name);
    if (schedule_profile_row == NULL) {
        vty_out(vty, "schedule_profile_row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Perform some checks, but only if the profile is not strict. The strict */
    /* profile does not contain any queues. */
    if (strcmp(schedule_profile_name, OVSREC_QUEUE_ALGORITHM_STRICT) != 0) {
        /* Check that the profile is complete. */
        if (!qos_schedule_profile_is_complete(schedule_profile_row)) {
            vty_out(vty, "schedule_profile_row cannot be incomplete.%s", VTY_NEWLINE);
            cli_do_config_abort(txn);
            return CMD_OVSDB_FAILURE;
        }

        /* Check that profiles contain all the same queues. */
        if (!qos_profiles_contain_same_queues(queue_profile_row,
                schedule_profile_row)) {
            vty_out(vty, "queue_profile_row and schedule_profile_row cannot contain different queues.%s", VTY_NEWLINE);
            cli_do_config_abort(txn);
            return CMD_OVSDB_FAILURE;
        }
    }

    /* Retrieve the system row. */
    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    if (system_row == NULL) {
        vty_out(vty, "System row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Set the profiles in the system row. */
    ovsrec_system_set_q_profile(system_row, queue_profile_row);
    ovsrec_system_set_qos(system_row, schedule_profile_row);

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_apply_global,
        qos_apply_global_cmd,
        "apply qos queue-profile NAME schedule-profile NAME",
        "Apply a configuration\n"
        "Configure QoS\n"
        "The queue-profile to apply\n"
        "The queue-profile to apply\n"
        "The schedule-profile to apply\n"
        "The schedule-profile to apply\n") {
    const char *queue_profile_name = argv[0];
    const char *schedule_profile_name = argv[1];

    return qos_apply_global_command(queue_profile_name, schedule_profile_name);
}

DEFUN (qos_apply_global_strict,
        qos_apply_global_strict_cmd,
        "apply qos queue-profile NAME schedule-profile strict",
        "Apply a configuration\n"
        "Configure QoS\n"
        "The queue-profile to apply\n"
        "The queue-profile to apply\n"
        "The schedule-profile to apply\n"
        "Use the strict schedule profile which has all queues configured to use the strict algorithm\n") {
    const char *queue_profile_name = argv[0];
    const char *schedule_profile_name = OVSREC_QUEUE_ALGORITHM_STRICT;

    return qos_apply_global_command(queue_profile_name, schedule_profile_name);
}

static vtysh_ret_val qos_apply_global_show_running_config_callback(
        void *p_private) {
    qos_queue_profile_show_running_config();
    qos_schedule_profile_show_running_config();

    return e_vtysh_ok;
}

void qos_apply_global_show_running_config(void) {
    vtysh_context_client client;
    memset(&client, 0, sizeof(vtysh_context_client));
    client.p_client_name = "qos_apply_global_show_running_config_callback";
    client.client_id = e_vtysh_config_context_qos_apply;
    client.p_callback = &qos_apply_global_show_running_config_callback;

    vtysh_ret_val retval = vtysh_context_addclient(
            e_vtysh_config_context, e_vtysh_config_context_qos_apply, &client);
    if(retval != e_vtysh_ok) {
        vty_out(vty, "Unable to add client callback.%s", VTY_NEWLINE);
    }
}

void qos_apply_global_vty_init(void) {
    install_element(CONFIG_NODE, &qos_apply_global_cmd);
    install_element(CONFIG_NODE, &qos_apply_global_strict_cmd);
}

void qos_apply_global_ovsdb_init(void) {
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_q_profile);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_qos);
}
