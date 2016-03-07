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

#include "qos_dscp_map_vty.h"

#include <libaudit.h>

#include "memory.h"
#include "openswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovsdb-idl.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "vswitch-idl.h"
#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_user.h"

/**
 * If defined, then the dscp map cos remark capability will be disabled.
 */
#define QOS_CAPABILITY_DSCP_MAP_COS_REMARK_DISABLED

VLOG_DEFINE_THIS_MODULE(vtysh_qos_dscp_map_cli);
extern struct ovsdb_idl *idl;

/**
 * Returns the dscp_map_entry for the given code_point.
 */
static struct ovsrec_qos_dscp_map_entry *
qos_dscp_map_row_for_code_point(
        int64_t code_point)
{
    const struct ovsrec_qos_dscp_map_entry *dscp_map_row;
    OVSREC_QOS_DSCP_MAP_ENTRY_FOR_EACH(dscp_map_row, idl) {
        if (dscp_map_row->code_point == code_point) {
            return (struct ovsrec_qos_dscp_map_entry *) dscp_map_row;
        }
    }

    return NULL;
}

/**
 * Executes the qos_dscp_map_command for the given
 * local_priority, priority_code_point, color, and description.
 */
static int
qos_dscp_map_command(int64_t code_point, int64_t local_priority,
        int64_t *priority_code_point, const char *color,
        const char *description)
{
    if (description != NULL) {
        if (!qos_is_valid_string(description)) {
            vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
            return CMD_OVSDB_FAILURE;
        }
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Retrieve the row. */
    struct ovsrec_qos_dscp_map_entry *dscp_map_row =
            qos_dscp_map_row_for_code_point(code_point);
    if (dscp_map_row == NULL) {
        vty_out(vty, "dscp map row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Update the row. */
    ovsrec_qos_dscp_map_entry_set_local_priority(dscp_map_row, local_priority);
    ovsrec_qos_dscp_map_entry_set_priority_code_point(dscp_map_row,
            priority_code_point, (priority_code_point == NULL ? 0 : 1));
    ovsrec_qos_dscp_map_entry_set_color(dscp_map_row,
            (color == NULL ? QOS_COLOR_DEFAULT : color));
    ovsrec_qos_dscp_map_entry_set_description(dscp_map_row,
            (description == NULL ? QOS_DESCRIPTION_DEFAULT : description));

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_dscp_map_command for the given
 * local_priority, priority_code_point, color, and description.
 */
DEFUN(qos_dscp_map_cos_remark_disabled,
        qos_dscp_map_cos_remark_disabled_cmd,
        "qos dscp-map <0-63> local-priority <0-7>\
 {color (green|yellow|red) | name STRING}",
        "Configure QoS\n"
        "Configure QoS DSCP Map\n"
        "The QoS DSCP Map code point\n"
        "Configure QoS DSCP Map local-priority\n"
        "The QoS DSCP Map local-priority\n"
        "Configure QoS DSCP Map color\n"
        "Set color to green\n"
        "Set color to yellow\n"
        "Set color to red\n"
        "Configure QoS DSCP Map name\n"
        "The QoS DSCP Map name\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: qos dscp-map", sizeof(aubuf));
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *code_point = argv[0];
    if (code_point != NULL) {
        char *cfg = audit_encode_nv_string("code_point", code_point, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }
    int64_t code_point_int = atoi(code_point);

    const char *local_priority = argv[1];
    if (local_priority != NULL) {
        char *cfg = audit_encode_nv_string(
                "local_priority", local_priority, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }
    int64_t local_priority_int = atoi(local_priority);

    const char *color = argv[2];
    if (color != NULL) {
        char *cfg = audit_encode_nv_string("color", color, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }

    const char *description = argv[3];
    if (description != NULL) {
        char *cfg = audit_encode_nv_string("description", description, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }

    int result = qos_dscp_map_command(code_point_int,
            local_priority_int, NULL, color, description);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG,
            aubuf, hostname, NULL, NULL, result);

    return result;
}

/**
 * Executes the qos_dscp_map_command for the given
 * local_priority, priority_code_point, color, and description.
 */
DEFUN(qos_dscp_map,
        qos_dscp_map_cmd,
        "qos dscp-map <0-63> local-priority <0-7>\
 {cos <0-7> | color (green|yellow|red) | name STRING}",
        "Configure QoS\n"
        "Configure QoS DSCP Map\n"
        "The QoS DSCP Map code point\n"
        "Configure QoS DSCP Map local-priority\n"
        "The QoS DSCP Map local-priority\n"
        "Configure the the 802.1Q priority.\n"
        "The 802.1Q priority that will be assigned to the packet\n"
        "Configure QoS DSCP Map color\n"
        "Set color to green\n"
        "Set color to yellow\n"
        "Set color to red\n"
        "Configure QoS DSCP Map name\n"
        "The QoS DSCP Map name\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: qos dscp-map", sizeof(aubuf));
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *code_point = argv[0];
    if (code_point != NULL) {
        char *cfg = audit_encode_nv_string("code_point", code_point, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }
    int64_t code_point_int = atoi(code_point);

    const char *local_priority = argv[1];
    if (local_priority != NULL) {
        char *cfg = audit_encode_nv_string(
                "local_priority", local_priority, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }
    int64_t local_priority_int = atoi(local_priority);

    const char *priority_code_point_string = argv[2];
    int64_t *priority_code_point = NULL;
    int64_t priority_code_point_value;
    if (priority_code_point_string != NULL) {
        priority_code_point = &priority_code_point_value;
        priority_code_point_value = atoi(priority_code_point_string);
    }
    if (priority_code_point_string != NULL) {
        char *cfg = audit_encode_nv_string(
                "priority_code_point_string", priority_code_point_string, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }

    const char *color = argv[3];
    if (color != NULL) {
        char *cfg = audit_encode_nv_string("color", color, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }

    const char *description = argv[4];
    if (description != NULL) {
        char *cfg = audit_encode_nv_string("description", description, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }

    int result = qos_dscp_map_command(code_point_int, local_priority_int,
            priority_code_point, color, description);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG,
            aubuf, hostname, NULL, NULL, result);

    return result;
}

/**
 * Executes the qos_dscp_map_no_command for the given code_point.
 */
static int
qos_dscp_map_no_command(int64_t code_point)
{
    /* Retrieve the row. */
    struct ovsrec_qos_dscp_map_entry *dscp_map_row =
            qos_dscp_map_row_for_code_point(code_point);
    if (dscp_map_row == NULL) {
        vty_out(vty, "dscp map row cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    int64_t local_priority = atoi(smap_get(&dscp_map_row->hw_defaults,
            QOS_DEFAULT_LOCAL_PRIORITY_KEY));
    int64_t priority_code_point = atoi(smap_get(&dscp_map_row->hw_defaults,
            QOS_DEFAULT_PRIORITY_CODE_POINT_KEY));
    const char *color = smap_get(&dscp_map_row->hw_defaults,
            QOS_DEFAULT_COLOR_KEY);
    const char *description = smap_get(&dscp_map_row->hw_defaults,
            QOS_DEFAULT_DESCRIPTION_KEY);

    int result = qos_dscp_map_command(code_point, local_priority,
            &priority_code_point, color, description);

    return result;
}

/**
 * Executes the qos_dscp_map_no_command for the given code_point.
 */
DEFUN(qos_dscp_map_no,
        qos_dscp_map_no_cmd,
        "no qos dscp-map <0-63> {local-priority <0-7> | cos <0-7>\
 | color (green|yellow|red) | name STRING}",
        NO_STR
        "Configure QoS\n"
        "Restore the QoS DSCP Map values for a given\
 code point to their factory default\n"
        "The QoS DSCP Map code point\n"
        "Configure QoS DSCP Map local-priority\n"
        "The QoS DSCP Map local-priority\n"
        "Configure the the 802.1Q priority.\n"
        "The 802.1Q priority that will be assigned to the packet\n"
        "Configure QoS DSCP Map color\n"
        "Set color to green\n"
        "Set color to yellow\n"
        "Set color to red\n"
        "Configure QoS DSCP Map name\n"
        "The QoS DSCP Map name\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE];
    strncpy(aubuf, "op=CLI: no qos dscp-map", sizeof(aubuf));
    char hostname[HOST_NAME_MAX+1];
    gethostname(hostname, HOST_NAME_MAX);
    int audit_fd = audit_open();

    const char *code_point = argv[0];
    if (code_point != NULL) {
        char *cfg = audit_encode_nv_string("code_point", code_point, 0);
        if (cfg != NULL) {
            strncat(aubuf, cfg, sizeof(aubuf));
            free(cfg);
        }
    }
    int64_t code_point_int = atoi(code_point);

    int result = qos_dscp_map_no_command(code_point_int);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG,
            aubuf, hostname, NULL, NULL, result);

    return result;
}

/**
 * Prints the given dscp_map_row. If is_default is true, then hw_defaults
 * will be printed.
 */
static void
print_dscp_map_row(struct ovsrec_qos_dscp_map_entry *dscp_map_row,
        bool is_default)
{
    int64_t code_point = is_default
            ? atoi(smap_get(&dscp_map_row->hw_defaults,
                    QOS_DEFAULT_CODE_POINT_KEY))
            : dscp_map_row->code_point;
    vty_out (vty, "%-10" PRId64 " ", code_point);

    int64_t local_priority = is_default
            ? atoi(smap_get(&dscp_map_row->hw_defaults,
                    QOS_DEFAULT_LOCAL_PRIORITY_KEY))
            : dscp_map_row->local_priority;
    vty_out (vty, "%-14" PRId64 " ", local_priority);

#ifdef QOS_CAPABILITY_DSCP_MAP_COS_REMARK_DISABLED
    /* Disabled for dill. */
#else
    char buffer[QOS_CLI_STRING_BUFFER_SIZE];
    buffer[0] = '\0';
    if (is_default) {
        strncpy(buffer,
                smap_get(&dscp_map_row->hw_defaults,
                QOS_DEFAULT_PRIORITY_CODE_POINT_KEY),
                sizeof(buffer));
    } else {
        if (dscp_map_row->priority_code_point != NULL) {
            snprintf(buffer, sizeof(buffer), "%" PRId64,
                    *dscp_map_row->priority_code_point);
        }
    }
    vty_out (vty, "%-3s ", buffer);
#endif

    const char *color = is_default
            ? smap_get(&dscp_map_row->hw_defaults, QOS_DEFAULT_COLOR_KEY)
            : dscp_map_row->color;
    vty_out (vty, "%-7s ", color);

    const char *description = is_default
            ? smap_get(&dscp_map_row->hw_defaults, QOS_DEFAULT_DESCRIPTION_KEY)
            : dscp_map_row->description;
    vty_out (vty, "%s ", description);

    vty_out (vty, "%s", VTY_NEWLINE);
}

/**
 * Executes the qos_dscp_map_show_command. If the given default_parameter
 * is not NULL, then the defaults will be shown.
 */
static int
qos_dscp_map_show_command(const char *default_parameter)
{
#ifdef QOS_CAPABILITY_DSCP_MAP_COS_REMARK_DISABLED
    /* cos is disabled for dill. */
    vty_out (vty, "code_point local_priority color   name%s", VTY_NEWLINE);
    vty_out (vty, "---------- -------------- ------- ----%s", VTY_NEWLINE);
#else
    vty_out (vty, "code_point local_priority cos color   name%s", VTY_NEWLINE);
    vty_out (vty, "---------- -------------- --- ------- ----%s", VTY_NEWLINE);
#endif

    /* Create an ordered array of rows. */
    struct ovsrec_qos_dscp_map_entry *dscp_map_rows[QOS_DSCP_MAP_ENTRY_COUNT];
    const struct ovsrec_qos_dscp_map_entry *dscp_map_row;
    OVSREC_QOS_DSCP_MAP_ENTRY_FOR_EACH(dscp_map_row, idl) {
        dscp_map_rows[dscp_map_row->code_point] =
                (struct ovsrec_qos_dscp_map_entry *) dscp_map_row;
    }

    /* Print the ordered rows. */
    bool is_default = (default_parameter != NULL);
    int i;
    for (i = 0; i < QOS_DSCP_MAP_ENTRY_COUNT; i++) {
        print_dscp_map_row(dscp_map_rows[i], is_default);
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_dscp_map_show_command. If the given default_parameter
 * is not NULL, then the defaults will be shown.
 */
DEFUN(qos_dscp_map_show,
    qos_dscp_map_show_cmd,
    "show qos dscp-map {default}",
    SHOW_STR
    "Show QoS Configuration\n"
    "Show QoS DSCP-Map Configuration\n"
    "Display the factory default values\n")
{
    const char *default_parameter = argv[0];

    return qos_dscp_map_show_command(default_parameter);
}

/**
 * Displays headers for the given code_point.
 */
static void
display_headers(bool *dscp_map_header_displayed,
        bool *code_point_header_displayed, int64_t code_point)
{
    if (!*dscp_map_header_displayed) {
        vty_out (vty, "qos dscp-map%s", VTY_NEWLINE);
        *dscp_map_header_displayed = true;
    }

    if (!*code_point_header_displayed) {
        vty_out (vty, "    code_point %" PRId64 "%s", code_point, VTY_NEWLINE);
        *code_point_header_displayed = true;
    }
}

/**
 * Contains the callback function for qos_dscp_map_show_running_config.
 */
static vtysh_ret_val
qos_dscp_map_show_running_config_callback(
        void *p_private)
{
    bool dscp_map_header_displayed = false;
    const struct ovsrec_qos_dscp_map_entry *dscp_map_row;
    OVSREC_QOS_DSCP_MAP_ENTRY_FOR_EACH(dscp_map_row, idl) {
        int64_t code_point = dscp_map_row->code_point;
        bool code_point_header_displayed = false;

        /* Show local_priority. */
        int64_t default_local_priority = atoi(smap_get(
                &dscp_map_row->hw_defaults, QOS_DEFAULT_LOCAL_PRIORITY_KEY));
        if (dscp_map_row->local_priority != default_local_priority) {
            display_headers(&dscp_map_header_displayed,
                    &code_point_header_displayed, code_point);
            vty_out(vty, "        local_priority %" PRId64 "%s",
                    dscp_map_row->local_priority, VTY_NEWLINE);
        }

#ifdef QOS_CAPABILITY_DSCP_MAP_COS_REMARK_DISABLED
        /* cos is disabled for dill. */
#else
        /* Show priority_code_point. */
        char current_priority_code_point[QOS_CLI_STRING_BUFFER_SIZE];
        if (dscp_map_row->priority_code_point == NULL) {
            strncpy(current_priority_code_point,
                    QOS_CLI_EMPTY_DISPLAY_STRING,
                    sizeof(current_priority_code_point));
        } else {
            snprintf(current_priority_code_point,
                    sizeof(current_priority_code_point), "%" PRId64,
                    *dscp_map_row->priority_code_point);
        }
        char default_priority_code_point[QOS_CLI_STRING_BUFFER_SIZE];
        int64_t default_priority_code_point_int =
                atoi(smap_get(&dscp_map_row->hw_defaults,
                        QOS_DEFAULT_PRIORITY_CODE_POINT_KEY));
        snprintf(default_priority_code_point,
                sizeof(default_priority_code_point), "%d",
                    default_priority_code_point_int);
        if (strncmp(current_priority_code_point,
                default_priority_code_point,
                sizeof(current_priority_code_point)) != 0) {
            display_headers(&dscp_map_header_displayed,
                    &code_point_header_displayed, code_point);
            vty_out(vty, "        cos %s%s",
                    current_priority_code_point, VTY_NEWLINE);
        }
#endif

        /* Show color. */
        const char *default_color =
                smap_get(&dscp_map_row->hw_defaults, QOS_DEFAULT_COLOR_KEY);
        if (strncmp(dscp_map_row->color, default_color,
                QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            display_headers(&dscp_map_header_displayed,
                    &code_point_header_displayed, code_point);
            vty_out(vty, "        color %s%s", dscp_map_row->color,
                    VTY_NEWLINE);
        }

        /* Show description. */
        const char *default_description =
                smap_get(&dscp_map_row->hw_defaults, QOS_DEFAULT_DESCRIPTION_KEY);
        if (strncmp(dscp_map_row->description, default_description,
                QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            char description[QOS_CLI_STRING_BUFFER_SIZE];
            if (strncmp(dscp_map_row->description, "",
                    QOS_CLI_STRING_BUFFER_SIZE) == 0) {
                strncpy(description, QOS_CLI_EMPTY_DISPLAY_STRING,
                        sizeof(description));
            } else {
                strncpy(description, dscp_map_row->description,
                        sizeof(description));
            }

            display_headers(&dscp_map_header_displayed,
                    &code_point_header_displayed, code_point);
            vty_out(vty, "        name %s%s", description,
                    VTY_NEWLINE);
        }
    }

    return e_vtysh_ok;
}

/**
 * Installs the callback function for qos_dscp_map_show_running_config.
 */
void
qos_dscp_map_show_running_config(void)
{
    vtysh_context_client client;
    memset(&client, 0, sizeof(vtysh_context_client));
    client.p_client_name = "qos_dscp_map_show_running_config_callback";
    client.client_id = e_vtysh_config_context_qos_dscp_map;
    client.p_callback = &qos_dscp_map_show_running_config_callback;

    vtysh_ret_val retval = vtysh_context_addclient(e_vtysh_config_context,
            e_vtysh_config_context_qos_dscp_map, &client);
    if(retval != e_vtysh_ok) {
        vty_out(vty, "Unable to add client callback.%s", VTY_NEWLINE);
    }
}

/**
 * Initializes qos_dscp_map_vty.
 */
void
qos_dscp_map_vty_init(void)
{
#ifdef QOS_CAPABILITY_DSCP_MAP_COS_REMARK_DISABLED
    /* For dill, there is no cos parameter for the dscp map command. */
    install_element(CONFIG_NODE, &qos_dscp_map_cos_remark_disabled_cmd);
#else
    install_element(CONFIG_NODE, &qos_dscp_map_cmd);
#endif
    install_element(CONFIG_NODE, &qos_dscp_map_no_cmd);
    install_element (ENABLE_NODE, &qos_dscp_map_show_cmd);
}

/**
 * Initializes qos_dscp_map_ovsdb.
 */
void
qos_dscp_map_ovsdb_init(void)
{
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_qos_dscp_map_entries);

    ovsdb_idl_add_table(idl, &ovsrec_table_qos_dscp_map_entry);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_code_point);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_local_priority);
    ovsdb_idl_add_column(idl,
            &ovsrec_qos_dscp_map_entry_col_priority_code_point);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_color);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_description);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_hw_defaults);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_external_ids);
}
