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
#include "qos_dscp_map_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"

#define QOS_CAPABILITY_DSCP_MAP_COS_REMARK_DISABLED

VLOG_DEFINE_THIS_MODULE(vtysh_qos_dscp_map_cli);
extern struct ovsdb_idl *idl;

static struct ovsrec_qos_dscp_map_entry *qos_dscp_map_row_for_code_point(
        int64_t code_point) {
    const struct ovsrec_qos_dscp_map_entry *dscp_map_row;
    OVSREC_QOS_DSCP_MAP_ENTRY_FOR_EACH(dscp_map_row, idl) {
        if (dscp_map_row->code_point == code_point) {
            return (struct ovsrec_qos_dscp_map_entry *) dscp_map_row;
        }
    }

    return NULL;
}

static void set_dscp_map_entry(struct ovsrec_qos_dscp_map_entry *dscp_map_entry,
        int64_t code_point, int64_t local_priority,
        int64_t priority_code_point, char *color, char *description) {
    dscp_map_entry->code_point = code_point;
    dscp_map_entry->local_priority = local_priority;
    *dscp_map_entry->priority_code_point = priority_code_point;
    dscp_map_entry->color = color;
    dscp_map_entry->description = description;
}

static struct ovsrec_qos_dscp_map_entry *qos_create_default_dscp_map(void) {
    struct ovsrec_qos_dscp_map_entry *dscp_map = xmalloc(
            sizeof(struct ovsrec_qos_dscp_map_entry) * QOS_DSCP_MAP_ENTRY_COUNT);

    /* Allocate each priority_code_point field. */
    int code_point;
    for (code_point = 0; code_point < QOS_DSCP_MAP_ENTRY_COUNT; code_point++) {
        dscp_map[code_point].priority_code_point = xmalloc(sizeof(int64_t));
    }

    set_dscp_map_entry(&dscp_map[0], 0, 0, 1, "green", "CS0");
    set_dscp_map_entry(&dscp_map[1], 1, 0, 1, "green", "");
    set_dscp_map_entry(&dscp_map[2], 2, 0, 1, "green", "");
    set_dscp_map_entry(&dscp_map[3], 3, 0, 1, "green", "");
    set_dscp_map_entry(&dscp_map[4], 4, 0, 1, "green", "");
    set_dscp_map_entry(&dscp_map[5], 5, 0, 1, "green", "");
    set_dscp_map_entry(&dscp_map[6], 6, 0, 1, "green", "");
    set_dscp_map_entry(&dscp_map[7], 7, 0, 1, "green", "");
    set_dscp_map_entry(&dscp_map[8], 8, 1, 0, "green", "CS1");
    set_dscp_map_entry(&dscp_map[9], 9, 1, 0, "green", "");

    set_dscp_map_entry(&dscp_map[10], 10, 1, 0, "green", "AF11");
    set_dscp_map_entry(&dscp_map[11], 11, 1, 0, "green", "");
    set_dscp_map_entry(&dscp_map[12], 12, 1, 0, "yellow", "AF12");
    set_dscp_map_entry(&dscp_map[13], 13, 1, 0, "green", "");
    set_dscp_map_entry(&dscp_map[14], 14, 1, 0, "red", "AF13");
    set_dscp_map_entry(&dscp_map[15], 15, 1, 0, "green", "");
    set_dscp_map_entry(&dscp_map[16], 16, 2, 2, "green", "CS2");
    set_dscp_map_entry(&dscp_map[17], 17, 2, 2, "green", "");
    set_dscp_map_entry(&dscp_map[18], 18, 2, 2, "green", "AF21");
    set_dscp_map_entry(&dscp_map[19], 19, 2, 2, "green", "");

    set_dscp_map_entry(&dscp_map[20], 20, 2, 2, "yellow", "AF22");
    set_dscp_map_entry(&dscp_map[21], 21, 2, 2, "green", "");
    set_dscp_map_entry(&dscp_map[22], 22, 2, 2, "red", "AF23");
    set_dscp_map_entry(&dscp_map[23], 23, 2, 2, "green", "");
    set_dscp_map_entry(&dscp_map[24], 24, 3, 3, "green", "CS3");
    set_dscp_map_entry(&dscp_map[25], 25, 3, 3, "green", "");
    set_dscp_map_entry(&dscp_map[26], 26, 3, 3, "green", "AF31");
    set_dscp_map_entry(&dscp_map[27], 27, 3, 3, "green", "");
    set_dscp_map_entry(&dscp_map[28], 28, 3, 3, "yellow", "AF32");
    set_dscp_map_entry(&dscp_map[29], 29, 3, 3, "green", "");

    set_dscp_map_entry(&dscp_map[30], 30, 3, 3, "red", "AF33");
    set_dscp_map_entry(&dscp_map[31], 31, 3, 3, "green", "");
    set_dscp_map_entry(&dscp_map[32], 32, 4, 4, "green", "CS4");
    set_dscp_map_entry(&dscp_map[33], 33, 4, 4, "green", "");
    set_dscp_map_entry(&dscp_map[34], 34, 4, 4, "green", "AF41");
    set_dscp_map_entry(&dscp_map[35], 35, 4, 4, "green", "");
    set_dscp_map_entry(&dscp_map[36], 36, 4, 4, "yellow", "AF42");
    set_dscp_map_entry(&dscp_map[37], 37, 4, 4, "green", "");
    set_dscp_map_entry(&dscp_map[38], 38, 4, 4, "red", "AF43");
    set_dscp_map_entry(&dscp_map[39], 39, 4, 4, "green", "");

    set_dscp_map_entry(&dscp_map[40], 40, 5, 5, "green", "CS5");
    set_dscp_map_entry(&dscp_map[41], 41, 5, 5, "green", "");
    set_dscp_map_entry(&dscp_map[42], 42, 5, 5, "green", "");
    set_dscp_map_entry(&dscp_map[43], 43, 5, 5, "green", "");
    set_dscp_map_entry(&dscp_map[44], 44, 5, 5, "green", "");
    set_dscp_map_entry(&dscp_map[45], 45, 5, 5, "green", "");
    set_dscp_map_entry(&dscp_map[46], 46, 5, 5, "green", "EF");
    set_dscp_map_entry(&dscp_map[47], 47, 5, 5, "green", "");
    set_dscp_map_entry(&dscp_map[48], 48, 6, 6, "green", "CS6");
    set_dscp_map_entry(&dscp_map[49], 49, 6, 6, "green", "");

    set_dscp_map_entry(&dscp_map[50], 50, 6, 6, "green", "");
    set_dscp_map_entry(&dscp_map[51], 51, 6, 6, "green", "");
    set_dscp_map_entry(&dscp_map[52], 52, 6, 6, "green", "");
    set_dscp_map_entry(&dscp_map[53], 53, 6, 6, "green", "");
    set_dscp_map_entry(&dscp_map[54], 54, 6, 6, "green", "");
    set_dscp_map_entry(&dscp_map[55], 55, 6, 6, "green", "");
    set_dscp_map_entry(&dscp_map[56], 56, 7, 7, "green", "CS7");
    set_dscp_map_entry(&dscp_map[57], 57, 7, 7, "green", "");
    set_dscp_map_entry(&dscp_map[58], 58, 7, 7, "green", "");
    set_dscp_map_entry(&dscp_map[59], 59, 7, 7, "green", "");

    set_dscp_map_entry(&dscp_map[60], 60, 7, 7, "green", "");
    set_dscp_map_entry(&dscp_map[61], 61, 7, 7, "green", "");
    set_dscp_map_entry(&dscp_map[62], 62, 7, 7, "green", "");
    set_dscp_map_entry(&dscp_map[63], 63, 7, 7, "green", "");

    return dscp_map;
}

static void qos_destroy_default_dscp_map(struct ovsrec_qos_dscp_map_entry *dscp_map) {
    if (dscp_map == NULL) {
        return;
    }

    /* Free each priority_code_point field. */
    int code_point;
    for (code_point = 0; code_point < QOS_DSCP_MAP_ENTRY_COUNT; code_point++) {
        free(dscp_map[code_point].priority_code_point);
    }

    free(dscp_map);
}

static int qos_dscp_map_command(int64_t code_point, int64_t local_priority,
        int64_t *priority_code_point, const char *color,
        const char *description) {
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

DEFUN (qos_dscp_map_cos_remark_disabled,
        qos_dscp_map_cos_remark_disabled_cmd,
        "qos dscp-map <0-63> local-priority <0-7> {color (green|yellow|red) | name STRING}",
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
        "The QoS DSCP Map name\n") {
    int64_t code_point = atoi(argv[0]);
    int64_t local_priority = atoi(argv[1]);
    const char *color = argv[2];
    const char *description = argv[3];

    return qos_dscp_map_command(code_point,
            local_priority, NULL, color, description);
}

DEFUN (qos_dscp_map,
        qos_dscp_map_cmd,
        "qos dscp-map <0-63> local-priority <0-7> {cos <0-7> | color (green|yellow|red) | name STRING}",
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
        "The QoS DSCP Map name\n") {
    int64_t code_point = atoi(argv[0]);
    int64_t local_priority = atoi(argv[1]);

    const char *priority_code_point_string = argv[2];
    int64_t *priority_code_point = NULL;
    int64_t priority_code_point_value;
    if (priority_code_point_string != NULL) {
        priority_code_point = &priority_code_point_value;
        priority_code_point_value = atoi(priority_code_point_string);
    }

    const char *color = argv[3];
    const char *description = argv[4];

    return qos_dscp_map_command(code_point, local_priority,
            priority_code_point, color, description);
}

static int qos_dscp_map_no_command(int64_t code_point) {
    struct ovsrec_qos_dscp_map_entry *default_dscp_map =
            qos_create_default_dscp_map();

    int i;
    for (i = 0; i < QOS_DSCP_MAP_ENTRY_COUNT; i++) {
        struct ovsrec_qos_dscp_map_entry default_dscp_map_entry =
                default_dscp_map[i];
        if (code_point == default_dscp_map_entry.code_point) {
            qos_dscp_map_command(
                    default_dscp_map_entry.code_point,
                    default_dscp_map_entry.local_priority,
                    default_dscp_map_entry.priority_code_point,
                    default_dscp_map_entry.color,
                    default_dscp_map_entry.description);
        }
    }

    qos_destroy_default_dscp_map(default_dscp_map);

    return CMD_SUCCESS;
}

DEFUN (qos_dscp_map_no,
        qos_dscp_map_no_cmd,
        "no qos dscp-map <0-63> {local-priority <0-7> | cos <0-7> | color (green|yellow|red) | name STRING}",
        NO_STR
        "Configure QoS\n"
        "Restore the QoS DSCP Map values for a given code point to their factory default\n"
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
        "The QoS DSCP Map name\n") {
    int64_t code_point = atoi(argv[0]);

    return qos_dscp_map_no_command(code_point);
}

static void print_dscp_map_row(struct ovsrec_qos_dscp_map_entry *dscp_map_row) {
    char buffer[QOS_CLI_STRING_BUFFER_SIZE];

    vty_out (vty, "%-10d ", (int) dscp_map_row->code_point);

    vty_out (vty, "%-14d ", (int) dscp_map_row->local_priority);

    buffer[0] = '\0';
    if (dscp_map_row->priority_code_point != NULL) {
        sprintf(buffer, "%d", (int) *dscp_map_row->priority_code_point);
    }
    vty_out (vty, "%-3s ", buffer);

    vty_out (vty, "%-7s ", dscp_map_row->color);

    buffer[0] = '\0';
    if (strcmp(dscp_map_row->description, "") != 0) {
        sprintf(buffer, "\"%s\"", dscp_map_row->description);
    }
    vty_out (vty, "%s ", buffer);

    vty_out (vty, "%s", VTY_NEWLINE);
}

static int qos_dscp_map_show_command(const char *default_parameter) {
    vty_out (vty, "code_point local_priority cos color   name%s", VTY_NEWLINE);
    vty_out (vty, "---------- -------------- --- ------- ----%s", VTY_NEWLINE);

    if (default_parameter != NULL) {
        /* Show default map. */
        struct ovsrec_qos_dscp_map_entry *default_dscp_map =
                qos_create_default_dscp_map();

        int i;
        for (i = 0; i < QOS_DSCP_MAP_ENTRY_COUNT; i++) {
            print_dscp_map_row(&default_dscp_map[i]);
        }

        qos_destroy_default_dscp_map(default_dscp_map);
    } else {
        /* Show the active map. */

        /* Create an ordered array of rows. */
        struct ovsrec_qos_dscp_map_entry *dscp_map_rows[QOS_DSCP_MAP_ENTRY_COUNT];
        const struct ovsrec_qos_dscp_map_entry *dscp_map_row;
        OVSREC_QOS_DSCP_MAP_ENTRY_FOR_EACH(dscp_map_row, idl) {
            dscp_map_rows[dscp_map_row->code_point] =
                    (struct ovsrec_qos_dscp_map_entry *) dscp_map_row;
        }

        /* Print the ordered rows. */
        int i;
        for (i = 0; i < QOS_DSCP_MAP_ENTRY_COUNT; i++) {
            print_dscp_map_row(dscp_map_rows[i]);
        }
    }

    return CMD_SUCCESS;
}

DEFUN (qos_dscp_map_show,
    qos_dscp_map_show_cmd,
    "show qos dscp-map {default}",
    SHOW_STR
    "Show QoS Configuration\n"
    "Show QoS DSCP-Map Configuration\n"
    "Display the factory default values\n") {
    const char *default_parameter = argv[0];

    return qos_dscp_map_show_command(default_parameter);
}

static void display_headers(bool *dscp_map_header_displayed,
        bool *code_point_header_displayed, int64_t code_point) {
    if (!*dscp_map_header_displayed) {
        vty_out (vty, "qos dscp-map%s", VTY_NEWLINE);
        *dscp_map_header_displayed = true;
    }

    if (!*code_point_header_displayed) {
        vty_out (vty, "    code_point %d%s", (int) code_point, VTY_NEWLINE);
        *code_point_header_displayed = true;
    }
}

static vtysh_ret_val qos_dscp_map_show_running_config_callback(
        void *p_private) {
    struct ovsrec_qos_dscp_map_entry *default_dscp_map =
            qos_create_default_dscp_map();

    bool dscp_map_header_displayed = false;
    int i;
    for (i = 0; i < QOS_DSCP_MAP_ENTRY_COUNT; i++) {
        struct ovsrec_qos_dscp_map_entry default_dscp_map_entry =
                default_dscp_map[i];

        const struct ovsrec_qos_dscp_map_entry *dscp_map_row;
        OVSREC_QOS_DSCP_MAP_ENTRY_FOR_EACH(dscp_map_row, idl) {
            int64_t code_point = dscp_map_row->code_point;
            if (dscp_map_row->code_point
                    == default_dscp_map_entry.code_point) {
                bool code_point_header_displayed = false;

                /* Show local_priority. */
                if (dscp_map_row->local_priority
                        != default_dscp_map_entry.local_priority) {
                    display_headers(&dscp_map_header_displayed,
                            &code_point_header_displayed, code_point);
                    vty_out(vty, "        local_priority %d%s",
                            (int) dscp_map_row->local_priority, VTY_NEWLINE);
                }

                /* Show priority_code_point. */
                char current_priority_code_point[QOS_CLI_STRING_BUFFER_SIZE];
                if (dscp_map_row->priority_code_point == NULL) {
                    strcpy(current_priority_code_point,
                            QOS_CLI_EMPTY_DISPLAY_STRING);
                } else {
                    sprintf(current_priority_code_point, "%d",
                            (int) *dscp_map_row->priority_code_point);
                }
                char default_priority_code_point[QOS_CLI_STRING_BUFFER_SIZE];
                if (default_dscp_map_entry.priority_code_point == NULL) {
                    strcpy(default_priority_code_point,
                            QOS_CLI_EMPTY_DISPLAY_STRING);
                } else {
                    sprintf(default_priority_code_point, "%d",
                            (int) *default_dscp_map_entry.priority_code_point);
                }
                if (strcmp(current_priority_code_point,
                        default_priority_code_point) != 0) {
                    display_headers(&dscp_map_header_displayed,
                            &code_point_header_displayed, code_point);
                    vty_out(vty, "        cos %s%s",
                            current_priority_code_point, VTY_NEWLINE);
                }

                /* Show color. */
                if (strcmp(dscp_map_row->color, default_dscp_map_entry.color)
                        != 0) {
                    display_headers(&dscp_map_header_displayed,
                            &code_point_header_displayed, code_point);
                    vty_out(vty, "        color %s%s", dscp_map_row->color,
                            VTY_NEWLINE);
                }

                /* Show description. */
                if (strcmp(dscp_map_row->description,
                        default_dscp_map_entry.description) != 0) {
                    char description[QOS_CLI_STRING_BUFFER_SIZE];
                    if (strcmp(dscp_map_row->description, "") == 0) {
                        strcpy(description, QOS_CLI_EMPTY_DISPLAY_STRING);
                    } else {
                        sprintf(description, "\"%s\"",
                                dscp_map_row->description);
                    }

                    display_headers(&dscp_map_header_displayed,
                            &code_point_header_displayed, code_point);
                    vty_out(vty, "        name %s%s", description,
                            VTY_NEWLINE);
                }
            }
        }
    }

    qos_destroy_default_dscp_map(default_dscp_map);

    return e_vtysh_ok;
}

void qos_dscp_map_show_running_config(void) {
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

void qos_dscp_map_vty_init(void) {
#ifdef QOS_CAPABILITY_DSCP_MAP_COS_REMARK_DISABLED
    /* For toronto, there is no cos parameter for the dscp map command. */
    install_element(CONFIG_NODE, &qos_dscp_map_cos_remark_disabled_cmd);
#else
    install_element(CONFIG_NODE, &qos_dscp_map_cmd);
#endif
    install_element(CONFIG_NODE, &qos_dscp_map_no_cmd);
    install_element (ENABLE_NODE, &qos_dscp_map_show_cmd);
}

void qos_dscp_map_ovsdb_init(void) {
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_qos_dscp_map_entries);

    ovsdb_idl_add_table(idl, &ovsrec_table_qos_dscp_map_entry);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_code_point);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_local_priority);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_priority_code_point);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_color);
    ovsdb_idl_add_column(idl, &ovsrec_qos_dscp_map_entry_col_description);
}
