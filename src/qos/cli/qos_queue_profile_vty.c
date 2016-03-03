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
#include "qos_queue_profile_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_queue_profile_cli);
extern struct ovsdb_idl *idl;

static char g_profile_name[QOS_CLI_STRING_BUFFER_SIZE];

static bool queue_has_local_priority(
        struct ovsrec_q_profile_entry *queue_row,
        int64_t local_priority) {
    int i;
    for (i = 0; i < queue_row->n_local_priorities; i++) {
        if (queue_row->local_priorities[i] == local_priority) {
            return true;
        }
    }

    return false;
}

struct ovsrec_q_profile *qos_get_queue_profile_row(
        const char *profile_name) {
    const struct ovsrec_q_profile *profile_row;
    OVSREC_Q_PROFILE_FOR_EACH(profile_row, idl) {
        if (strncmp(profile_row->name, profile_name, QOS_CLI_MAX_STRING_LENGTH) == 0) {
            return (struct ovsrec_q_profile *) profile_row;
        }
    }

    return NULL;
}

static struct ovsrec_q_profile_entry *qos_get_queue_profile_entry_row(
        struct ovsrec_q_profile *profile_row, int64_t queue_num) {
    int i;
    for (i = 0; i < profile_row->n_q_profile_entries; i++) {
        if (profile_row->key_q_profile_entries[i] == queue_num) {
            return profile_row->value_q_profile_entries[i];
        }
    }

    return NULL;
}

bool qos_queue_profile_has_queue_num(struct ovsrec_q_profile *profile_row,
        int64_t queue_num) {
    int j;
    for (j = 0; j < profile_row->n_q_profile_entries; j++) {
        int64_t profile_queue_num = profile_row->key_q_profile_entries[j];
        if (queue_num == profile_queue_num) {
            return true;
        }
    }

    return false;
}

bool qos_queue_profile_is_complete(struct ovsrec_q_profile *profile_row,
        bool print_error) {
    bool found_local_priorities[QOS_LOCAL_PRIORITY_COUNT];
    int i;
    for (i = 0; i < QOS_LOCAL_PRIORITY_COUNT; i++) {
        found_local_priorities[i] = false;
    }

    /* Validate that each local priority does not appear more than once. */
    int j;
    for (j = 0; j < profile_row->n_q_profile_entries; j++) {
        struct ovsrec_q_profile_entry *queue_row =
                profile_row->value_q_profile_entries[j];
        for (i = 0; i < queue_row->n_local_priorities; i++) {
            int64_t local_priority = queue_row->local_priorities[i];
            if (found_local_priorities[local_priority] == true) {
                if (print_error) {
                    vty_out(vty, "The queue profile has local priority %d assigned more than once.%s",
                            (int) local_priority, VTY_NEWLINE);
                }
                return false;
            }
            found_local_priorities[local_priority] = true;
        }
    }

    /* Validate that all local priorities have been assigned. */
    for (i = 0; i < QOS_LOCAL_PRIORITY_COUNT; i++) {
        if (found_local_priorities[i] == false) {
            if (print_error) {
                vty_out(vty, "The queue profile is missing local priority %d.%s",
                        i, VTY_NEWLINE);
            }
            return false;
        }
    }

    return true;
}

static bool is_row_applied(const struct ovsrec_q_profile *profile_row) {
    if (profile_row == NULL) {
        return false;
    }

    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    if (system_row->q_profile == profile_row) {
        return true;
    }

    const struct ovsrec_port *port_row;
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        if (port_row->q_profile == profile_row) {
            return true;
        }
    }

    return false;
}

static bool is_applied(const char *profile_name) {
    struct ovsrec_q_profile *profile_row = qos_get_queue_profile_row(
            profile_name);

    return is_row_applied(profile_row);
}

static bool is_row_hw_default(const struct ovsrec_q_profile *profile_row) {
    if (profile_row == NULL) {
        return false;
    }

    if (profile_row->hw_default == NULL) {
        return false;
    }

    return *profile_row->hw_default;
}

static bool is_hw_default(const char *profile_name) {
    struct ovsrec_q_profile *profile_row = qos_get_queue_profile_row(
            profile_name);

    return is_row_hw_default(profile_row);
}

static struct ovsrec_q_profile_entry *insert_queue_row(
        struct ovsrec_q_profile *profile_row, int64_t queue_num,
        struct ovsdb_idl_txn *txn) {
    /* Create the queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            ovsrec_q_profile_entry_insert(txn);

    /* Update the profile row. */
    int64_t *key_list =
            xmalloc(sizeof(int64_t) *
                    (profile_row->n_q_profile_entries + 1));
    struct ovsrec_q_profile_entry **value_list =
            xmalloc(sizeof *profile_row->value_q_profile_entries *
                    (profile_row->n_q_profile_entries + 1));

    int i;
    for (i = 0; i < profile_row->n_q_profile_entries; i++) {
        key_list[i] = profile_row->key_q_profile_entries[i];
        value_list[i] = profile_row->value_q_profile_entries[i];
    }
    key_list[profile_row->n_q_profile_entries] = queue_num;
    value_list[profile_row->n_q_profile_entries] = queue_row;
    ovsrec_q_profile_set_q_profile_entries(profile_row, key_list,
            value_list, profile_row->n_q_profile_entries + 1);
    free(key_list);
    free(value_list);

    return queue_row;
}

static bool qos_queue_profile_command(struct ovsdb_idl_txn *txn,
        const char *profile_name) {
    /* Retrieve the row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        /* Create a new row. */
        profile_row = ovsrec_q_profile_insert(txn);
        ovsrec_q_profile_set_name(profile_row, profile_name);
    }

    return false;
}

static int qos_queue_profile_command_commit(const char *profile_name) {
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(profile_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (strncmp(profile_name, OVSREC_QUEUE_ALGORITHM_STRICT, QOS_CLI_MAX_STRING_LENGTH) == 0) {
        vty_out(vty, "The profile name cannot be '%s'.%s",
                OVSREC_QUEUE_ALGORITHM_STRICT, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty, "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    bool error = qos_queue_profile_command(txn, profile_name);
    if (error) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    snprintf(g_profile_name, QOS_CLI_MAX_STRING_LENGTH, "%s", profile_name);
    vty->node = QOS_QUEUE_PROFILE_NODE;
    vty->index = g_profile_name;
    return CMD_SUCCESS;
}

DEFUN (qos_queue_profile,
        qos_queue_profile_cmd,
       "qos queue-profile NAME",
       "Configure QoS\n"
       "Set the QoS Queue Profile configuration\n"
       "The name of the Queue Profile\n") {
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: qos queue-profile", QOS_CLI_AUDIT_BUFFER_SIZE);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *profile_name = argv[0];
    if (profile_name != NULL) {
        char *cfg = audit_encode_nv_string("profile_name", profile_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }

    int result = qos_queue_profile_command_commit(profile_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static bool qos_queue_profile_no_command(struct ovsdb_idl_txn *txn,
        const char *profile_name) {
    /* Retrieve the row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return true;
    }

    if (strncmp(profile_name, QOS_DEFAULT_NAME, QOS_CLI_MAX_STRING_LENGTH) == 0) {
        /* For the profile named 'default', restore the factory defaults. */

        /* Delete all default profile queue rows. */
        ovsrec_q_profile_set_q_profile_entries(profile_row, NULL, NULL, 0);

        /* Retrieve the factory default row. */
        struct ovsrec_q_profile *factory_default_profile_row =
                qos_get_queue_profile_row(QOS_FACTORY_DEFAULT_NAME);
        if (factory_default_profile_row == NULL) {
            vty_out(vty, "Profile %s does not exist.%s",
                    QOS_FACTORY_DEFAULT_NAME, VTY_NEWLINE);
            return true;
        }

        /* Copy all factory defaults into new entry rows. */
        int64_t queue_row_count =
                factory_default_profile_row->n_q_profile_entries;
        int64_t *key_list =
                xmalloc(sizeof(int64_t) *
                        queue_row_count);
        struct ovsrec_q_profile_entry **value_list =
                xmalloc(sizeof *profile_row->value_q_profile_entries *
                        queue_row_count);
        int j;
        for (j = 0; j < queue_row_count; j++) {
            struct ovsrec_q_profile_entry *queue_row =
                    ovsrec_q_profile_entry_insert(txn);
            struct ovsrec_q_profile_entry *default_row =
                    factory_default_profile_row->value_q_profile_entries[j];
            ovsrec_q_profile_entry_set_description(queue_row,
                    default_row->description);
            ovsrec_q_profile_entry_set_local_priorities(
                    queue_row, default_row->local_priorities,
                    default_row->n_local_priorities);
            key_list[j] = factory_default_profile_row->key_q_profile_entries[j];
            value_list[j] = queue_row;
        }

        /* Add the new entry rows to the profile row. */
        ovsrec_q_profile_set_q_profile_entries(profile_row, key_list,
                value_list, queue_row_count);
        free(key_list);
        free(value_list);
    } else {
        /* If not the profile named 'default', delete the row. */
        ovsrec_q_profile_delete(profile_row);
    }

    return false;
}

static int qos_queue_profile_no_command_commit(const char *profile_name) {
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(profile_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (strncmp(profile_name, OVSREC_QUEUE_ALGORITHM_STRICT, QOS_CLI_MAX_STRING_LENGTH) == 0) {
        vty_out(vty, "The profile name cannot be '%s'.%s",
                OVSREC_QUEUE_ALGORITHM_STRICT, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty, "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    bool error = qos_queue_profile_no_command(txn, profile_name);
    if (error) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_queue_profile_no,
        qos_queue_profile_no_cmd,
        "no qos queue-profile NAME",
        NO_STR
        "Configure QoS\n"
        "Deletes a Queue Profile, if it is not currently applied\n"
        "The name of the Queue Profile to delete\n") {
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: no qos queue-profile", QOS_CLI_AUDIT_BUFFER_SIZE);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *profile_name = argv[0];
    if (profile_name != NULL) {
        char *cfg = audit_encode_nv_string("profile_name", profile_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }

    int result = qos_queue_profile_no_command_commit(profile_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static bool qos_queue_profile_name_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num, const char *queue_name) {
    /* Retrieve the profile row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return true;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            qos_get_queue_profile_entry_row(profile_row, queue_num);

    /* If no existing row, then insert a new queue row. */
    if (queue_row == NULL) {
        queue_row = insert_queue_row(profile_row, queue_num, txn);
    }

    /* Update the queue row. */
    ovsrec_q_profile_entry_set_description(queue_row, queue_name);

    return false;
}

static int qos_queue_profile_name_command_commit(const char *profile_name,
        int64_t queue_num, const char *queue_name) {
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (queue_name == NULL) {
        vty_out(vty, "queue_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(queue_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty, "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    bool error = qos_queue_profile_name_command(txn, profile_name,
            queue_num, queue_name);
    if (error) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_queue_profile_name,
        qos_queue_profile_name_cmd,
       "name queue <0-7> NAME",
       "Configure the name of a queue in a Queue Profile\n"
       "Sets the name of a queue\n"
       "The number of the queue\n"
       "The name of the queue\n") {
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: name queue", QOS_CLI_AUDIT_BUFFER_SIZE);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *profile_name = (char*) vty->index;
    if (profile_name != NULL) {
        char *cfg = audit_encode_nv_string("profile_name", profile_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }

    const char *queue_num = argv[0];
    if (queue_num != NULL) {
        char *cfg = audit_encode_nv_string("queue_num", queue_num, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }
    int64_t queue_num_int = atoi(queue_num);

    const char *queue_name = argv[1];
    if (queue_name != NULL) {
        char *cfg = audit_encode_nv_string("queue_name", queue_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }

    int result = qos_queue_profile_name_command_commit(profile_name, queue_num_int,
            queue_name);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static bool has_content(struct ovsrec_q_profile_entry *queue_row) {
    if ((queue_row->description == NULL) &&
            (queue_row->local_priorities == NULL ||
                    queue_row->n_local_priorities == 0)) {
        return false;
    } else {
        return true;
    }
}

static void delete_queue_row(
        struct ovsrec_q_profile *profile_row, int64_t queue_num) {
    int64_t *key_list =
            xmalloc(sizeof(int64_t) *
                    (profile_row->n_q_profile_entries - 1));
    struct ovsrec_q_profile_entry **value_list =
            xmalloc(sizeof *profile_row->value_q_profile_entries *
                    (profile_row->n_q_profile_entries - 1));
    int i;
    int j = 0;
    for (i = 0; i < profile_row->n_q_profile_entries; i++) {
        if (profile_row->key_q_profile_entries[i] != queue_num) {
            key_list[j] = profile_row->key_q_profile_entries[i];
            value_list[j] = profile_row->value_q_profile_entries[i];
            j++;
        }
    }
    ovsrec_q_profile_set_q_profile_entries(profile_row, key_list,
            value_list, profile_row->n_q_profile_entries - 1);
    free(key_list);
    free(value_list);
}

static bool qos_queue_profile_name_no_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num) {
    /* Retrieve the profile row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return true;;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            qos_get_queue_profile_entry_row(profile_row, queue_num);
    if (queue_row == NULL) {
        vty_out(vty, "Profile %s does not have queue_num %d configured.%s",
                profile_name, (int) queue_num, VTY_NEWLINE);
        return true;
    }

    /* Update the queue row. */
    ovsrec_q_profile_entry_set_description(queue_row, NULL);

    /* If row has no content, then delete the queue row. */
    if (!has_content(queue_row)) {
        delete_queue_row(profile_row, queue_num);
    }

    return false;
}

static int qos_queue_profile_name_no_command_commit(const char *profile_name,
        int64_t queue_num) {
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty, "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    bool error = qos_queue_profile_name_no_command(txn,
            profile_name, queue_num);
    if (error) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_queue_profile_name_no,
        qos_queue_profile_name_no_cmd,
        "no name queue <0-7> {NAME}",
        NO_STR
        "Configure the name of a queue in a Queue Profile\n"
        "Deletes the name of a queue\n"
        "The number of the queue\n"
        "The name of the queue\n") {
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: no name queue", QOS_CLI_AUDIT_BUFFER_SIZE);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *profile_name = (char*) vty->index;
    if (profile_name != NULL) {
        char *cfg = audit_encode_nv_string("profile_name", profile_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }

    const char *queue_num = argv[0];
    if (queue_num != NULL) {
        char *cfg = audit_encode_nv_string("queue_num", queue_num, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }
    int64_t queue_num_int = atoi(queue_num);

    int result = qos_queue_profile_name_no_command_commit(profile_name, queue_num_int);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static void add_local_priority(struct ovsrec_q_profile_entry *queue_row,
        int64_t local_priority) {
    if (queue_has_local_priority(queue_row, local_priority)) {
        return;
    }

    /* local_priority was not found, so add it. */
    int64_t *value_list =
            xmalloc(sizeof(int64_t) *
                    (queue_row->n_local_priorities + 1));
    int i;
    for (i = 0; i < queue_row->n_local_priorities; i++) {
        value_list[i] = queue_row->local_priorities[i];
    }
    value_list[queue_row->n_local_priorities] = local_priority;
    ovsrec_q_profile_entry_set_local_priorities(
            queue_row, value_list, queue_row->n_local_priorities + 1);
    free(value_list);
}

static bool qos_queue_profile_map_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num, int64_t local_priority) {
    /* Retrieve the profile row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return true;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            qos_get_queue_profile_entry_row(profile_row, queue_num);

    /* If no existing row, then insert a new queue row. */
    if (queue_row == NULL) {
        queue_row = insert_queue_row(profile_row, queue_num, txn);
    }

    /* Update the queue row. */
    add_local_priority(queue_row, local_priority);

    return false;
}

static int qos_queue_profile_map_command_commit(const char *profile_name,
        int64_t queue_num, int64_t local_priority) {
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty, "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    bool error = qos_queue_profile_map_command(txn, profile_name,
            queue_num, local_priority);
    if (error) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_queue_profile_map,
        qos_queue_profile_map_cmd,
       "map queue <0-7> local-priority <0-7>",
       "Configure the local-priority map for a queue in a Queue Profile\n"
       "Configure the local-priority map for a queue in a Queue Profile\n"
       "The number of the queue\n"
       "The local-priority to configure\n"
       "The local-priority to configure\n") {
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: map queue", QOS_CLI_AUDIT_BUFFER_SIZE);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *profile_name = (char*) vty->index;
    if (profile_name != NULL) {
        char *cfg = audit_encode_nv_string("profile_name", profile_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }

    const char *queue_num = argv[0];
    if (queue_num != NULL) {
        char *cfg = audit_encode_nv_string("queue_num", queue_num, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }
    int64_t queue_num_int = atoi(queue_num);

    const char *local_priority = argv[1];
    if (local_priority != NULL) {
        char *cfg = audit_encode_nv_string("local_priority", local_priority, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }
    int64_t local_priority_int = atoi(local_priority);

    int result = qos_queue_profile_map_command_commit(profile_name, queue_num_int,
            local_priority_int);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static void remove_local_priority(
        struct ovsrec_q_profile_entry *queue_row,
        int64_t local_priority) {
    if (!queue_has_local_priority(queue_row, local_priority)) {
        return;
    }

    /* local_priority was found, so remove it. */
    int64_t *value_list =
            xmalloc(sizeof(int64_t) *
                    (queue_row->n_local_priorities - 1));
    int i;
    int j = 0;
    for (i = 0; i < queue_row->n_local_priorities; i++) {
        if (queue_row->local_priorities[i] != local_priority) {
            value_list[j] = queue_row->local_priorities[i];
            j++;
        }
    }
    ovsrec_q_profile_entry_set_local_priorities(
            queue_row, value_list, queue_row->n_local_priorities - 1);
    free(value_list);
}

static bool qos_queue_profile_map_no_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num, int64_t *local_priority) {
    /* Retrieve the profile row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return true;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            qos_get_queue_profile_entry_row(profile_row, queue_num);
    if (queue_row == NULL) {
        vty_out(vty, "Profile %s does not have queue_num %d configured.%s",
                profile_name, (int) queue_num, VTY_NEWLINE);
        return true;
    }

    /* Update the queue row. */
    if (local_priority == NULL) {
        /* Delete all local-priorities. */
        ovsrec_q_profile_entry_set_local_priorities(
                queue_row, NULL, 0);
    } else {
        /* Delete a single local-priority. */
        remove_local_priority(queue_row, *local_priority);
    }

    /* If row has no content, then delete the queue row. */
    if (!has_content(queue_row)) {
        delete_queue_row(profile_row, queue_num);
    }

    return false;
}

static int qos_queue_profile_map_no_command_commit(const char *profile_name,
        int64_t queue_num, int64_t *local_priority) {
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty, "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    bool error = qos_queue_profile_map_no_command(txn, profile_name,
            queue_num, local_priority);
    if (error) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_queue_profile_map_no,
        qos_queue_profile_map_no_cmd,
       "no map queue <0-7> {local-priority <0-7>}",
       NO_STR
       "Configure the local-priority map for a queue in a Queue Profile\n"
       "Deletes the local-priority for a queue in a Queue Profile\n"
       "The number of the queue\n"
       "The local-priority to delete\n"
       "The local-priority to delete\n") {
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: no map queue", QOS_CLI_AUDIT_BUFFER_SIZE);
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *profile_name = (char*) vty->index;
    if (profile_name != NULL) {
        char *cfg = audit_encode_nv_string("profile_name", profile_name, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }

    const char *queue_num = argv[0];
    if (queue_num != NULL) {
        char *cfg = audit_encode_nv_string("queue_num", queue_num, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }
    int64_t queue_num_int = atoi(queue_num);

    const char *local_priority_string = argv[1];
    int64_t *local_priority = NULL;
    int64_t local_priority_value;
    if (local_priority_string != NULL) {
        local_priority = &local_priority_value;
        local_priority_value = atoi(local_priority_string);
    }
    if (local_priority_string != NULL) {
        char *cfg = audit_encode_nv_string("local_priority_string", local_priority_string, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, QOS_CLI_STRING_BUFFER_SIZE);
            free(cfg);
        }
    }

    int result = qos_queue_profile_map_no_command_commit(profile_name, queue_num_int,
            local_priority);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG, aubuf, hostname, NULL, NULL, result);

    return result;
}

static void snprintf_local_priorities(char *buffer, int64_t n,
        struct ovsrec_q_profile_entry *profile_entry_row) {
    int i;
    for (i = 0; i < profile_entry_row->n_local_priorities; i++) {
        buffer += snprintf(buffer, n,
                "%d", (int) profile_entry_row->local_priorities[i]);

        /* If not the last one, then print a comma. */
        if (i < profile_entry_row->n_local_priorities - 1) {
            buffer += snprintf(buffer, n, ",");
        }
    }
}

static void print_queue_profile_entry_row(int64_t queue_num,
        struct ovsrec_q_profile_entry *profile_entry_row) {
    char buffer[QOS_CLI_STRING_BUFFER_SIZE];

    vty_out (vty, "%-9d ", (int) queue_num);

    buffer[0] = '\0';
    snprintf_local_priorities(buffer, QOS_CLI_STRING_BUFFER_SIZE, profile_entry_row);
    vty_out (vty, "%-16s ", buffer);

    buffer[0] = '\0';
    if (profile_entry_row->description != NULL &&
            strncmp(profile_entry_row->description, "", QOS_CLI_MAX_STRING_LENGTH) != 0) {
        snprintf(buffer, QOS_CLI_STRING_BUFFER_SIZE, "%s", profile_entry_row->description);
    }
    vty_out (vty, "%s ", buffer);

    vty_out (vty, "%s", VTY_NEWLINE);
}

static int qos_queue_profile_show_command(const char *name) {
    if (name == NULL) {
        vty_out(vty, "name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsrec_q_profile *profile_row = qos_get_queue_profile_row(name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                name, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    vty_out (vty, "queue_num local_priorities name%s", VTY_NEWLINE);
    vty_out (vty, "--------- ---------------- ----%s", VTY_NEWLINE);

    int i;
    for (i = 0; i < profile_row->n_q_profile_entries; i++) {
        print_queue_profile_entry_row(profile_row->key_q_profile_entries[i],
                profile_row->value_q_profile_entries[i]);
    }

    return CMD_SUCCESS;
}

DEFUN (qos_queue_profile_show,
    qos_queue_profile_show_cmd,
    "show qos queue-profile NAME",
    SHOW_STR
    "Show QoS Configuration\n"
    "Show QoS Queue Profile Configuration\n"
    "The name of the Queue Profile to display\n") {
    const char *name = argv[0];

    return qos_queue_profile_show_command(name);
}

static int qos_queue_profile_show_all_command(void) {
    vty_out (vty, "profile_status profile_name%s", VTY_NEWLINE);
    vty_out (vty, "-------------- ------------%s", VTY_NEWLINE);

    char buffer[QOS_CLI_STRING_BUFFER_SIZE];

    const struct ovsrec_q_profile *profile_row;
    OVSREC_Q_PROFILE_FOR_EACH(profile_row, idl) {
        if (is_row_applied(profile_row)) {
            vty_out (vty, "applied        ");
        } else if (qos_queue_profile_is_complete(
                (struct ovsrec_q_profile *) profile_row, false)) {
            vty_out (vty, "complete       ");
        } else {
            vty_out (vty, "incomplete     ");
        }

        buffer[0] = '\0';
        if (profile_row->name != NULL &&
                strncmp(profile_row->name, "", QOS_CLI_MAX_STRING_LENGTH) != 0) {
            snprintf(buffer, QOS_CLI_STRING_BUFFER_SIZE, "%s", profile_row->name);
        }
        vty_out (vty, "%s ", buffer);

        vty_out (vty, "%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN (qos_queue_profile_show_all,
    qos_queue_profile_show_all_cmd,
    "show qos queue-profile",
    SHOW_STR
    "Show QoS Configuration\n"
    "Show QoS Queue Profile Configuration\n") {
    return qos_queue_profile_show_all_command();
}

static void display_headers(bool *header_displayed,
        bool *queue_num_header_displayed, int64_t queue_num) {
    if (!*header_displayed) {
        vty_out (vty, "qos queue-profile%s", VTY_NEWLINE);
        *header_displayed = true;
    }

    if (!*queue_num_header_displayed) {
        vty_out (vty, "    queue_num %d%s", (int) queue_num, VTY_NEWLINE);
        *queue_num_header_displayed = true;
    }
}

static void display_header(bool *header_displayed) {
    bool ignore_queue_num = true;
    display_headers(header_displayed, &ignore_queue_num, -1);
}

void qos_queue_profile_show_running_config(void) {
    struct ovsrec_q_profile *default_profile_row = qos_get_queue_profile_row(
            QOS_FACTORY_DEFAULT_NAME);
    if (default_profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                QOS_FACTORY_DEFAULT_NAME, VTY_NEWLINE);
        return;
    }

    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    struct ovsrec_q_profile *applied_profile_row = system_row->q_profile;

    bool header_displayed = false;
    /* Show profile name. */
    if (strncmp(applied_profile_row->name, default_profile_row->name, QOS_CLI_MAX_STRING_LENGTH) != 0 &&
            strncmp(applied_profile_row->name, QOS_DEFAULT_NAME, QOS_CLI_MAX_STRING_LENGTH) != 0) {
        display_header(&header_displayed);
        vty_out(vty, "    name %s%s",
                applied_profile_row->name, VTY_NEWLINE);
    }

    int i;
    for (i = 0; i < default_profile_row->n_q_profile_entries; i++) {
        int64_t default_queue_num =
                default_profile_row->key_q_profile_entries[i];
        struct ovsrec_q_profile_entry *default_profile_entry =
                default_profile_row->value_q_profile_entries[i];

        struct ovsrec_q_profile_entry *applied_profile_entry =
                qos_get_queue_profile_entry_row(
                        applied_profile_row, default_queue_num);
        if (applied_profile_entry == NULL) {
            /* If the applied profile does not contain a queue_num from the */
            /* default profile, then skip to the next queue_num. */
            continue;
        }

        bool queue_num_header_displayed = false;

        /* Show local-priorities. */
        char default_buffer[QOS_CLI_STRING_BUFFER_SIZE];
        default_buffer[0] = '\0';
        char applied_buffer[QOS_CLI_STRING_BUFFER_SIZE];
        applied_buffer[0] = '\0';
        snprintf_local_priorities(default_buffer, QOS_CLI_STRING_BUFFER_SIZE, default_profile_entry);
        snprintf_local_priorities(applied_buffer, QOS_CLI_STRING_BUFFER_SIZE, applied_profile_entry);
        if (strncmp(applied_buffer, default_buffer, QOS_CLI_MAX_STRING_LENGTH) != 0) {
            display_headers(&header_displayed,
                    &queue_num_header_displayed, default_queue_num);
            vty_out(vty, "        local_priorities %s%s",
                    applied_buffer, VTY_NEWLINE);
        }

        /* Show description. */
        char applied_description[QOS_CLI_STRING_BUFFER_SIZE];
        if (applied_profile_entry->description == NULL) {
            strncpy(applied_description, QOS_CLI_EMPTY_DISPLAY_STRING, QOS_CLI_EMPTY_DISPLAY_STRING_BUFFER_SIZE);
        } else {
            snprintf(applied_description, QOS_CLI_STRING_BUFFER_SIZE, "%d",
                    *applied_profile_entry->description);
        }
        char default_description[QOS_CLI_STRING_BUFFER_SIZE];
        if (default_profile_entry->description == NULL) {
            strncpy(default_description, QOS_CLI_EMPTY_DISPLAY_STRING, QOS_CLI_EMPTY_DISPLAY_STRING_BUFFER_SIZE);
        } else {
            snprintf(default_description, QOS_CLI_STRING_BUFFER_SIZE, "%d",
                    *default_profile_entry->description);
        }
        if (strncmp(applied_description, default_description, QOS_CLI_MAX_STRING_LENGTH) != 0) {
            display_headers(&header_displayed,
                    &queue_num_header_displayed, default_queue_num);
            vty_out(vty, "        name %s%s",
                    applied_description, VTY_NEWLINE);
        }
    }
}

void qos_queue_profile_vty_init(void) {
    install_element(CONFIG_NODE, &qos_queue_profile_cmd);
    install_element(CONFIG_NODE, &qos_queue_profile_no_cmd);
    install_element(ENABLE_NODE, &qos_queue_profile_show_cmd);
    install_element(ENABLE_NODE, &qos_queue_profile_show_all_cmd);

    install_element(QOS_QUEUE_PROFILE_NODE, &qos_queue_profile_name_cmd);
    install_element(QOS_QUEUE_PROFILE_NODE, &qos_queue_profile_name_no_cmd);

    install_element(QOS_QUEUE_PROFILE_NODE, &qos_queue_profile_map_cmd);
    install_element(QOS_QUEUE_PROFILE_NODE, &qos_queue_profile_map_no_cmd);
}

void qos_queue_profile_ovsdb_init(void) {
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_q_profile);

    ovsdb_idl_add_table(idl, &ovsrec_table_q_profile);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_q_profile_entries);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_hw_default);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_external_ids);

    ovsdb_idl_add_table(idl, &ovsrec_table_q_profile_entry);
    ovsdb_idl_add_column(idl,
            &ovsrec_q_profile_entry_col_local_priorities);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_entry_col_description);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_entry_col_hw_default);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_entry_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_entry_col_external_ids);
}
