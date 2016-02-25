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
#include "qos_cos_map_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_cos_map_cli);
extern struct ovsdb_idl *idl;

static struct ovsrec_qos_cos_map_entry *qos_cos_map_row_for_code_point(
        int64_t code_point) {
    const struct ovsrec_qos_cos_map_entry *cos_map_row;
    OVSREC_QOS_COS_MAP_ENTRY_FOR_EACH(cos_map_row, idl) {
        if (cos_map_row->code_point == code_point) {
            return (struct ovsrec_qos_cos_map_entry *) cos_map_row;
        }
    }

    return NULL;
}

static void set_cos_map_entry(struct ovsrec_qos_cos_map_entry *cos_map_entry,
        int64_t code_point, int64_t local_priority, char *color,
        char *description) {
    cos_map_entry->code_point = code_point;
    cos_map_entry->local_priority = local_priority;
    cos_map_entry->color = color;
    cos_map_entry->description = description;
}

static struct ovsrec_qos_cos_map_entry *qos_create_default_cos_map(void) {
    struct ovsrec_qos_cos_map_entry *cos_map = xmalloc(
            sizeof(struct ovsrec_qos_cos_map_entry) * QOS_COS_MAP_ENTRY_COUNT);
    set_cos_map_entry(&cos_map[0], 0, 1, "green", "Best_Effort");
    set_cos_map_entry(&cos_map[1], 1, 0, "green", "Background");
    set_cos_map_entry(&cos_map[2], 2, 2, "green", "Excellent_Effort");
    set_cos_map_entry(&cos_map[3], 3, 3, "green", "Critical_Applications");
    set_cos_map_entry(&cos_map[4], 4, 4, "green", "Video");
    set_cos_map_entry(&cos_map[5], 5, 5, "green", "Voice");
    set_cos_map_entry(&cos_map[6], 6, 6, "green", "Internetwork_Control");
    set_cos_map_entry(&cos_map[7], 7, 7, "green", "Network_Control");

    return cos_map;
}

static void qos_destroy_default_cos_map(struct ovsrec_qos_cos_map_entry *cos_map) {
    if (cos_map == NULL) {
        return;
    }

    free(cos_map);
}

static int qos_cos_map_command(int64_t code_point, int64_t local_priority,
        const char *color, const char *description) {
    if (description != NULL) {
        if (!qos_is_valid_string(description)) {
            vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
            return CMD_SUCCESS;
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
    struct ovsrec_qos_cos_map_entry *cos_map_row =
            qos_cos_map_row_for_code_point(code_point);
    if (cos_map_row == NULL) {
        vty_out(vty, "cos map row cannot be NULL.%s", VTY_NEWLINE);
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    /* Update the row. */
    ovsrec_qos_cos_map_entry_set_local_priority(cos_map_row, local_priority);
    ovsrec_qos_cos_map_entry_set_color(cos_map_row,
            (color == NULL ? QOS_COLOR_DEFAULT : color));
    ovsrec_qos_cos_map_entry_set_description(cos_map_row,
            (description == NULL ? QOS_DESCRIPTION_DEFAULT : description));

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

DEFUN (qos_cos_map,
        qos_cos_map_cmd,
        "qos cos-map <0-7> local-priority <0-7> {color (green|yellow|red) | name STRING}",
        "Configure QoS\n"
        "Configure QoS COS Map\n"
        "The QoS COS Map code point\n"
        "Configure QoS COS Map local-priority\n"
        "The QoS COS Map local-priority\n"
        "Configure QoS COS Map color\n"
        "Set color to green\n"
        "Set color to yellow\n"
        "Set color to red\n"
        "Configure QoS COS Map name\n"
        "The QoS COS Map name\n") {
    int64_t code_point = atoi(argv[0]);
    int64_t local_priority = atoi(argv[1]);
    const char *color = argv[2];
    const char *description = argv[3];

    return qos_cos_map_command(code_point, local_priority, color, description);
}

static int qos_cos_map_no_command(int64_t code_point) {
    struct ovsrec_qos_cos_map_entry *default_cos_map = qos_create_default_cos_map();

    int i;
    for (i = 0; i < QOS_COS_MAP_ENTRY_COUNT; i++) {
        struct ovsrec_qos_cos_map_entry default_cos_map_entry = default_cos_map[i];
        if (code_point == default_cos_map_entry.code_point) {
            qos_cos_map_command(
                    default_cos_map_entry.code_point,
                    default_cos_map_entry.local_priority,
                    default_cos_map_entry.color,
                    default_cos_map_entry.description);
        }
    }

    qos_destroy_default_cos_map(default_cos_map);

    return CMD_SUCCESS;
}

DEFUN (qos_cos_map_no,
        qos_cos_map_no_cmd,
        "no qos cos-map <0-7> {local-priority <0-7> | color (green|yellow|red) | name STRING}",
        NO_STR
        "Configure QoS\n"
        "Restore the QoS COS Map values for a given code point to their factory default\n"
        "The QoS COS Map code point\n"
        "Configure QoS COS Map local-priority\n"
        "The QoS COS Map local-priority\n"
        "Configure QoS COS Map color\n"
        "Set color to green\n"
        "Set color to yellow\n"
        "Set color to red\n"
        "Configure QoS COS Map name\n"
        "The QoS COS Map name\n") {
    int64_t code_point = atoi(argv[0]);

    return qos_cos_map_no_command(code_point);
}

static void print_cos_map_row(struct ovsrec_qos_cos_map_entry *cos_map_row) {
    char buffer[QOS_CLI_STRING_BUFFER_SIZE];

    vty_out (vty, "%-10d ", (int) cos_map_row->code_point);

    vty_out (vty, "%-14d ", (int) cos_map_row->local_priority);

    vty_out (vty, "%-7s ", cos_map_row->color);

    buffer[0] = '\0';
    if (cos_map_row->description != NULL &&
            strcmp(cos_map_row->description, "") != 0) {
        sprintf(buffer, "\"%s\"", cos_map_row->description);
    }
    vty_out (vty, "%s ", buffer);

    vty_out (vty, "%s", VTY_NEWLINE);
}

static int qos_cos_map_show_command(const char *default_parameter) {
    vty_out (vty, "code_point local_priority color   name%s", VTY_NEWLINE);
    vty_out (vty, "---------- -------------- ------- ----%s", VTY_NEWLINE);

    if (default_parameter != NULL) {
        /* Show default map. */
        struct ovsrec_qos_cos_map_entry *default_cos_map =
                qos_create_default_cos_map();

        int i;
        for (i = 0; i < QOS_COS_MAP_ENTRY_COUNT; i++) {
            print_cos_map_row(&default_cos_map[i]);
        }

        qos_destroy_default_cos_map(default_cos_map);
    } else {
        /* Show the active map. */

        /* Create an ordered array of rows. */
        struct ovsrec_qos_cos_map_entry *cos_map_rows[QOS_COS_MAP_ENTRY_COUNT];
        const struct ovsrec_qos_cos_map_entry *cos_map_row;
        OVSREC_QOS_COS_MAP_ENTRY_FOR_EACH(cos_map_row, idl) {
            cos_map_rows[cos_map_row->code_point] =
                    (struct ovsrec_qos_cos_map_entry *) cos_map_row;
        }

        /* Print the ordered rows. */
        int i;
        for (i = 0; i < QOS_COS_MAP_ENTRY_COUNT; i++) {
            print_cos_map_row(cos_map_rows[i]);
        }
    }

    return CMD_SUCCESS;
}

DEFUN (qos_cos_map_show,
        qos_cos_map_show_cmd,
        "show qos cos-map {default}",
        SHOW_STR
        "Show QoS Configuration\n"
        "Show QoS COS-Map Configuration\n"
        "Display the factory default values\n") {
    const char *default_parameter = argv[0];

    return qos_cos_map_show_command(default_parameter);
}

static void display_headers(bool *cos_map_header_displayed,
        bool *code_point_header_displayed, int64_t code_point) {
    if (!*cos_map_header_displayed) {
        vty_out (vty, "qos cos-map%s", VTY_NEWLINE);
        *cos_map_header_displayed = true;
    }

    if (!*code_point_header_displayed) {
        vty_out (vty, "    code_point %d%s", (int) code_point, VTY_NEWLINE);
        *code_point_header_displayed = true;
    }
}

static vtysh_ret_val qos_cos_map_show_running_config_callback(void *p_private) {
    struct ovsrec_qos_cos_map_entry *default_cos_map = qos_create_default_cos_map();

    bool cos_map_header_displayed = false;
    int i;
    for (i = 0; i < QOS_COS_MAP_ENTRY_COUNT; i++) {
        struct ovsrec_qos_cos_map_entry default_cos_map_entry = default_cos_map[i];

        const struct ovsrec_qos_cos_map_entry *cos_map_row;
        OVSREC_QOS_COS_MAP_ENTRY_FOR_EACH(cos_map_row, idl) {
            int64_t code_point = cos_map_row->code_point;
            if (cos_map_row->code_point == default_cos_map_entry.code_point) {
                bool code_point_header_displayed = false;

                /* Show local_priority. */
                if (cos_map_row->local_priority
                        != default_cos_map_entry.local_priority) {
                    display_headers(&cos_map_header_displayed,
                            &code_point_header_displayed, code_point);
                    vty_out(vty, "        local_priority %d%s",
                            (int) cos_map_row->local_priority, VTY_NEWLINE);
                }

                /* Show color. */
                if (strcmp(cos_map_row->color, default_cos_map_entry.color)
                        != 0) {
                    display_headers(&cos_map_header_displayed,
                            &code_point_header_displayed, code_point);
                    vty_out(vty, "        color %s%s", cos_map_row->color,
                            VTY_NEWLINE);
                }

                /* Show description. */
                if (strcmp(cos_map_row->description,
                        default_cos_map_entry.description) != 0) {
                    char description[QOS_CLI_STRING_BUFFER_SIZE];
                    if (strcmp(cos_map_row->description, "") == 0) {
                        strcpy(description, QOS_CLI_EMPTY_DISPLAY_STRING);
                    } else {
                        sprintf(description, "\"%s\"",
                                cos_map_row->description);
                    }

                    display_headers(&cos_map_header_displayed,
                            &code_point_header_displayed, code_point);
                    vty_out(vty, "        name %s%s", description,
                            VTY_NEWLINE);
                }
            }
        }
    }

    qos_destroy_default_cos_map(default_cos_map);

    return e_vtysh_ok;
}

void qos_cos_map_show_running_config(void) {
    vtysh_context_client client;
    memset(&client, 0, sizeof(vtysh_context_client));
    client.p_client_name = "qos_cos_map_show_running_config_callback";
    client.client_id = e_vtysh_config_context_qos_cos_map;
    client.p_callback = &qos_cos_map_show_running_config_callback;

    vtysh_ret_val retval = vtysh_context_addclient(e_vtysh_config_context,
            e_vtysh_config_context_qos_cos_map, &client);
    if(retval != e_vtysh_ok) {
        vty_out(vty, "Unable to add client callback.%s", VTY_NEWLINE);
    }
}

void qos_cos_map_vty_init(void) {
    install_element(CONFIG_NODE, &qos_cos_map_cmd);
    install_element(CONFIG_NODE, &qos_cos_map_no_cmd);
    install_element (ENABLE_NODE, &qos_cos_map_show_cmd);
}

void qos_cos_map_ovsdb_init(void) {
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_qos_cos_map_entries);

    ovsdb_idl_add_table(idl, &ovsrec_table_qos_cos_map_entry);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_code_point);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_local_priority);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_color);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_description);
}
