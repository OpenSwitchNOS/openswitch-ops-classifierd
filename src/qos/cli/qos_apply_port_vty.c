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
#include "qos_apply_global_vty.h"
#include "qos_apply_port_vty.h"
#include "qos_schedule_profile_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_apply_port_cli);
extern struct ovsdb_idl *idl;

static int qos_apply_port_command(const char *port_name,
        const char *schedule_profile_name) {
    if (port_name == NULL) {
        vty_out(vty, "port_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (schedule_profile_name == NULL) {
        vty_out(vty, "schedule_profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(schedule_profile_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
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
        vty_out(vty, "QoS Schedule Profile cannot be configured on a member of a LAG.%s",
                VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Retrieve the system row. */
    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    if (system_row == NULL) {
        vty_out(vty, "System row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Get the queue profile from the system row. */
    struct ovsrec_q_profile *queue_profile_row = system_row->q_profile;

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

    /* Retrieve the port row. */
    struct ovsrec_port *port_row = port_row_for_name(port_name);
    if (port_row == NULL) {
        vty_out(vty, "Port row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Set the scheudle profile in the port row. */
    ovsrec_port_set_qos(port_row, schedule_profile_row);

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_apply_port,
        qos_apply_port_cmd,
        "apply qos schedule-profile NAME",
        "Apply a configuration\n"
        "Configure QoS\n"
        "The schedule-profile to apply\n"
        "The schedule-profile to apply\n") {
    char aubuf[160];
    strcpy(aubuf, "op=CLI: apply qos");
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

    const char *schedule_profile_name = argv[0];
    if (schedule_profile_name != NULL) {
        char *cfg = audit_encode_nv_string("schedule_profile_name", schedule_profile_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, 130);
            free(cfg);
        }
    }

    int result = qos_apply_port_command(port_name, schedule_profile_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

DEFUN (qos_apply_port_strict,
        qos_apply_port_strict_cmd,
        "apply qos schedule-profile strict",
        "Apply a configuration\n"
        "Configure QoS\n"
        "The schedule-profile to apply\n"
        "Use the strict schedule profile which has all queues configured to use the strict algorithm\n") {
    char aubuf[160];
    strcpy(aubuf, "op=CLI: apply qos");
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

    const char *schedule_profile_name = OVSREC_QUEUE_ALGORITHM_STRICT;
    if (schedule_profile_name != NULL) {
        char *cfg = audit_encode_nv_string("schedule_profile_name", schedule_profile_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, 130);
            free(cfg);
        }
    }

    int result = qos_apply_port_command(port_name, schedule_profile_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static int qos_apply_port_no_command(const char *port_name) {
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
        vty_out(vty, "QoS Schedule Profile cannot be configured on a member of a LAG.%s",
                VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Retrieve the port row. */
    struct ovsrec_port *port_row = port_row_for_name(port_name);
    if (port_row == NULL) {
        vty_out(vty, "Port row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Clear the schedule profile for the port row. */
    ovsrec_port_set_qos(port_row, NULL);

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_apply_port_no,
        qos_apply_port_no_cmd,
        "no apply qos schedule-profile {NAME}",
        NO_STR
        "Apply a configuration\n"
        "Configure QoS\n"
        "Clears the schedule profile\n"
        "The name of the schedule profile\n") {
    char aubuf[160];
    strcpy(aubuf, "op=CLI: no apply qos");
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

    int result = qos_apply_port_no_command(port_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

void qos_apply_port_vty_init(void) {
    install_element(INTERFACE_NODE, &qos_apply_port_cmd);
    install_element(INTERFACE_NODE, &qos_apply_port_strict_cmd);
    install_element(INTERFACE_NODE, &qos_apply_port_no_cmd);

    install_element(LINK_AGGREGATION_NODE, &qos_apply_port_cmd);
    install_element(LINK_AGGREGATION_NODE, &qos_apply_port_strict_cmd);
    install_element(LINK_AGGREGATION_NODE, &qos_apply_port_no_cmd);
}

void qos_apply_port_ovsdb_init(void) {
    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_qos);
}
