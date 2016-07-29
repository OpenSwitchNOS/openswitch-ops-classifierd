/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bridge.h"
#include "vrf.h"
#include "acl_port.h"
#include "vswitch-idl.h"
#include "dynamic-string.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"
#include "reconfigure-blocks.h"
#include "stats-blocks.h"
#include "acl_plugin.h"
#include "acl_ofproto.h"
#include "acl_log.h"
#include "ops_cls_status_msgs.h"
#include "openswitch-idl.h"


VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin_port);

/*************************************************************
 * acl_port_reconfigure_lag_iface structure
 *************************************************************/
 struct acl_port_reconfigure_lag_iface {
     struct ovs_list lag_iface_node;

     /*OpenFlow port number */
     ofp_port_t port_number;

     /* action to be performed */
     int action;
};

static void
acl_port_map_stats_get(struct acl_port_map *acl_port_map,
                       struct ofproto *ofproto);

/**************************************************************************//**
 * struct ops_cls_interface_info helper routine
 * Sets the interface_info structure
 *
 * @param[out] interface_info - Pointer to @see struct ops_cls_interface_info
 * @param[in]  acl_port       - Pointer to @see struct acl_port
 * @param[in]  port           - Pointer to @see struct port
 *****************************************************************************/
static void
ops_cls_interface_info_construct(struct ops_cls_interface_info *interface_info,
                                 const struct acl_port *acl_port,
                                 const struct port* port OVS_UNUSED)
{
    memset(interface_info, 0, sizeof *interface_info);

    /* TODO: handle more interface types when we know how to */
    interface_info->interface = OPS_CLS_INTERFACE_PORT;
    interface_info->flags |= acl_port->interface_flags;
}

/******************************************************************************
 * struct acl_port_map helper routines
 *****************************************************************************/

 /*************************************************************************//**
 * Sets the hw_acl field in the acl_port_map. This function is called after
 * an ACL has been successfully applied in hw to a port config
 * type (type, direction)
 *
 * @param[in] acl_port_map - Pointer to the port_map containing port info
 *                           for a given cfg (type, direction)
 * @param[in] acl          - Pointer to acl that was successfully applied
 *****************************************************************************/
static void
acl_port_map_set_hw_acl(struct acl_port_map *acl_port_map, struct acl *acl)
{
    /* Only do something if the hw_acl is really changing */
    if (acl_port_map->hw_acl != acl) {
        if (acl_port_map->hw_acl) {
            /* remove myself from the old one */
            list_remove(&acl_port_map->acl_node);
            /* Reset myself */
            list_init(&acl_port_map->acl_node);
        }
        acl_port_map->hw_acl = acl;
        if (acl_port_map->hw_acl) {
            /* add myself to the new one */
            list_push_back(&acl_port_map->hw_acl->acl_port_map, &acl_port_map->acl_node);
        }
    }
}

/**************************************************************************//**
 * Construct an acl_port_map for a given configuration (type, direction).
 * This function is called once when the port is seen by ACL plugin for the
 * first time.
 *
 * @param[in] acl_port_map - acl_port_map to construct
 * @param[in] acl_port     - Pointer to the acl_port structure
 * @param[in] index        - Index of the global array holding the relevant
 *                           configuration.
 *****************************************************************************/
static void
acl_port_map_construct(struct acl_port_map *acl_port_map,
                       struct acl_port *acl_port, off_t index)
{
    /* no allocation here. acl_port_map structs are stored in an array
       inside acl_port structs */
    acl_port_map->parent = acl_port;
    acl_port_map->acl_db = &acl_db_accessor[index];
    acl_port_map->hw_acl = NULL;
    list_init(&acl_port_map->acl_node);
}

/**************************************************************************//**
 * Destruct an acl_port_map for a given configuration (type, direction). This
 * function is called when a port delete request is received.
 *
 * @param[in] acl_port_map - acl_port_map to destruct
 * @param[in] acl_port     - Pointer to the acl_port structure
 * @param[in] index        - Index of the global array holding the relevant
 *                           configuration.
 *****************************************************************************/
static void
acl_port_map_destruct(struct acl_port_map *acl_port_map)
{
    /* If we eventually hook into a polite shutdown mechanism, we'll
     * need to replace these asserts with a call to
     * acl_port_map_set_hw_acl(acl_port_map, NULL). If we ever do that, we should
     * also make sure that we teardown acl_ports (and therefore these
     * acl_port_map records) before we teardown the acl records.
     *
     * Only during a polite shutdown should we be doing low-level
     * teardown on PI records that are still interconnected.
     *
     * Until the day we support polite shutdown I prefer these asserts
     * to catch code that's doing bad things.
     */
    ovs_assert(!acl_port_map->hw_acl);
    ovs_assert(list_is_empty(&acl_port_map->acl_node));

    /* no deallocation here. acl_port_map structs are stored in an array
       inside acl_port structs */
}

/**************************************************************************//**
 * Construct and set the cfg_status column of a given port row. This function
 * is called after a call to the classifier asic plugin. The status
 * is recorded and uploaded to OVSDB.
 *
 * @param[in] acl_port_map - Pointer to the acl_port_map to get relevant
 *                           database access calls.
 * @param[in] row          - Pointer to the IDL port row
 * @param[in] state        - State string for the status code
 * @param[in] code         - Status code
 * @param[in] details      - detailed message explaining the status of an
 *                           acl port operation
 *****************************************************************************/
static void
acl_port_map_set_cfg_status(struct acl_port_map *acl_port_map,
                            const struct ovsrec_port *row,
                            char *state, unsigned int code, char *details)
{
    char code_str[OPS_CLS_CODE_STR_MAX_LEN];
    char version[OPS_CLS_VERSION_STR_MAX_LEN];

    snprintf(version, OPS_CLS_VERSION_STR_MAX_LEN,
             "%" PRId64"", acl_db_util_get_cfg_version(acl_port_map->acl_db, row)[0]);
    acl_db_util_status_setkey(acl_port_map->acl_db, row,
                                OPS_CLS_STATUS_VERSION_STR, version);
    acl_db_util_status_setkey(acl_port_map->acl_db, row,
                                OPS_CLS_STATUS_STATE_STR, state);
    snprintf(code_str, OPS_CLS_CODE_STR_MAX_LEN, "%u", code);
    acl_db_util_status_setkey(acl_port_map->acl_db, row,
                                OPS_CLS_STATUS_CODE_STR, code_str);
    acl_db_util_status_setkey(acl_port_map->acl_db, row,
                                OPS_CLS_STATUS_MSG_STR, details);
}

/**************************************************************************//**
 * This function calls asic plugin API calls for a requested acl port
 * operation. Apply, Remove, Replace are currently supported actions.
 *
 * @param[in] acl_port_map - Pointer to the acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_update_cfg_internal(struct acl_port_map *acl_port_map,
                                 struct port *port, struct ofproto *ofproto,
                                 struct ovs_list *reconfigure_lag_ifaces_list)
{
    struct ops_cls_pd_status status;
    struct ops_cls_pd_list_status list_status;

    memset(&status, 0, sizeof status);
    memset(&list_status, 0, sizeof list_status);
    struct ops_cls_interface_info interface_info;
    ops_cls_interface_info_construct(&interface_info,
                                     acl_port_map->parent, port);
    int rc;
    const char *method_called = NULL;
    /* status_str used to store status description in db */
    char status_str[OPS_CLS_STATUS_MSG_MAX_LEN] = {0};
    unsigned int sequence_number = 0;
    int64_t clear_req_id = 0;
    int64_t clear_performed_id = 0;

    struct acl* acl;
    const struct ovsrec_acl *ovsdb_acl =
        acl_db_util_get_cfg(acl_port_map->acl_db, acl_port_map->parent->ovsdb_row);
    if (!ovsdb_acl) {
        /* The cfg being null means that acl_port_cfg_delete should have been
         * called instead of this function.
         */
        ovs_assert(0);
    }

    acl  = acl_lookup_by_uuid(&ovsdb_acl->header_.uuid);
    if (!acl) {
        /* This shouldn't happen because we currently process ACL
         * row changes before Port row changes. But once the
         * Change system is in place this really becomes
         * impossible. Changes will have dependencies and can
         * be reordered.
         */
         ovs_assert(0);
    }

    if (acl_port_map->hw_acl == acl) {

        if ((reconfigure_lag_ifaces_list != NULL) &&
            (list_size(reconfigure_lag_ifaces_list) > 0)) {
            struct acl_port_reconfigure_lag_iface * reconfigure_lag_iface;

            LIST_FOR_EACH(reconfigure_lag_iface, lag_iface_node,
                          reconfigure_lag_ifaces_list) {
                rc = call_ofproto_cls_lag_update(
                            acl,
                            port,
                            ofproto,
                            reconfigure_lag_iface->port_number,
                            reconfigure_lag_iface->action,
                            &interface_info,
                            acl_port_map->acl_db->direction,
                            &status);
                method_called = OPS_CLS_STATUS_MSG_OP_LAG_UPDATE_STR;
            }
        }

        /* Perform clear statistics if clear requested id and clear
         * performed id are different
         */
         clear_req_id = acl_db_util_get_clear_statistics_requested(
                                        acl_port_map->acl_db,
                                        acl_port_map->parent->ovsdb_row);
         clear_performed_id = acl_db_util_get_clear_statistics_performed(
                                        acl_port_map->acl_db,
                                        acl_port_map->parent->ovsdb_row);
        if (clear_req_id != clear_performed_id) {
            /* Call ASIC layer to clear statistics.
             * This field is set from UI when clear stats is requested.
             * We call ASIC layer to clear statistics and mark the
             * operation done by setting
             * aclv4_in_statistics_clear_performed column regardless of
             * result of the call.The UI is expected to look at this
             * column and reset the aclv4_in_statistics_clear_requested
             * column. We will then detect that the flag is reset and
             * reset our flag marking completion of the request/response
             * cycle
             */
            VLOG_DBG("ACL_PORT_MAP %s:%s:%s clearing statistics\n",
                     acl_port_map->parent->port->name,
                     ops_cls_type_strings[acl_port_map->acl_db->type],
                     ops_cls_direction_strings[
                                        acl_port_map->acl_db->direction]);
            rc = call_ofproto_ops_cls_statistics_clear(
                                                acl_port_map->hw_acl,
                                                acl_port_map->parent->port,
                                                ofproto,
                                                &interface_info,
                                                acl_port_map->acl_db->direction,
                                                &list_status);
            acl_log_handle_clear_stats(ovsdb_acl);
            acl_port_map_stats_get(acl_port_map, ofproto);
            method_called = OPS_CLS_STATUS_MSG_OP_CLEAR_STR;
        }
    } else if (!acl_port_map->hw_acl) {
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s applying %s",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction],
                 acl->name);
        if (strncmp(acl_port_map->parent->port->name, "lag", 3) != 0 ||
            acl_port_map->parent->lag_members_active) {
            rc = call_ofproto_ops_cls_apply(acl,
                                            port,
                                            ofproto,
                                            &interface_info,
                                            acl_port_map->acl_db->direction,
                                            &status);
            method_called = OPS_CLS_STATUS_MSG_OP_APPLY_STR;
        }
    } else {
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s replacing %s with %s",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction],
                 acl_port_map->hw_acl->name,
                 acl->name);
        rc = call_ofproto_ops_cls_replace(acl_port_map->hw_acl,
                                          acl,
                                          port,
                                          ofproto,
                                          &interface_info,
                                          acl_port_map->acl_db->direction,
                                          &status);
        method_called = OPS_CLS_STATUS_MSG_OP_REPLACE_STR;
    }

    if (method_called == NULL) {
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s no PD call needed",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction]);
    } else if (!strcmp(method_called, OPS_CLS_STATUS_MSG_OP_CLEAR_STR)) {
        /* Set the clear statistics performed column to match clear
         * statistics requested column
         */
        acl_db_util_set_clear_statistics_performed(acl_port_map->acl_db,
                                                   port->cfg,
                                                   clear_req_id);
        /* Print debug messages to note success or failure */
        if (rc == 0) {
             VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD %s succeeded",
                  acl_port_map->parent->port->name,
                  ops_cls_type_strings[acl_port_map->acl_db->type],
                  ops_cls_direction_strings[acl_port_map->acl_db->direction],
                  method_called);
        } else {
             VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD %s failed",
                  acl_port_map->parent->port->name,
                  ops_cls_type_strings[acl_port_map->acl_db->type],
                  ops_cls_direction_strings[acl_port_map->acl_db->direction],
                  method_called);
        }
    } else if (rc == 0) {
        /* success */
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD %s succeeded",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction],
                 method_called);
        if (strcmp(method_called, OPS_CLS_STATUS_MSG_OP_LAG_UPDATE_STR) != 0) {
            acl_port_map_set_hw_acl(acl_port_map, acl);
            acl_db_util_set_applied(acl_port_map->acl_db, port->cfg,
                                     acl->ovsdb_row);
            /* status_str will be empty string ("") on success */
            acl_port_map_set_cfg_status(acl_port_map, port->cfg,
                                        OPS_CLS_STATE_APPLIED_STR,
                                        status.status_code, status_str);
        }
    } else {
        /* failure */

        /* convert entry_id to sequence_number using cur_aces */
        if(status.entry_id < acl->ovsdb_row->n_cur_aces) {
            sequence_number = acl->ovsdb_row->key_cur_aces[status.entry_id];
        }
        ops_cls_status_msgs_get(status.status_code,
                                method_called,
                                OPS_CLS_STATUS_MSG_FEATURE_ACL_STR,
                                OPS_CLS_STATUS_MSG_IFACE_PORT_STR,
                                acl_port_map->parent->port->name,
                                sequence_number,
                                OPS_CLS_STATUS_MSG_MAX_LEN,
                                status_str);
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD %s failed",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction],
                 method_called);
        acl_port_map_set_cfg_status(acl_port_map, port->cfg,
                                    OPS_CLS_STATE_REJECTED_STR,
                                    status.status_code, status_str);
    }
}

/**************************************************************************//**
 * This function calls asic plugin API calls for a requested acl port
 * unapply operation. This function is called when a port is deleted.
 *
 * @param[in] acl_port_map - Pointer to the acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_unapply_internal(struct acl_port_map* acl_port_map,
                              struct port *port, struct ofproto *ofproto)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s unapply",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    ovs_assert(acl_port_map->hw_acl);

    /* Make the call down to the PD layer */
    struct ops_cls_pd_status status;
    memset(&status, 0, sizeof status);
    struct ops_cls_interface_info interface_info;
    ops_cls_interface_info_construct(&interface_info, acl_port_map->parent,
                                     port);

    int rc = call_ofproto_ops_cls_remove(acl_port_map->hw_acl,
                                         port,
                                         ofproto,
                                         &interface_info,
                                         acl_port_map->acl_db->direction,
                                         &status);
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD remove %s",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction],
             rc==0 ? "succeeded" : "failed");

    /* Unapply (like delete) often has to be assumed to have succeeded,
     * even if lower levels said it failed. This is because unapply
     * & delete are often called as a knee-jerk reaction to noticing that
     * something has already been deleted.
     *
     * So, ignore rc and clear out our record from the acl.
     */
    acl_port_map_set_hw_acl(acl_port_map, NULL);
    if (strncmp(port->name, "lag", 3) != 0) {
        acl_db_util_set_applied(acl_port_map->acl_db, port->cfg, NULL);
        acl_port_map_set_cfg_status(acl_port_map, port->cfg,
                                    rc == 0 ? OPS_CLS_STATE_APPLIED_STR
                                            : OPS_CLS_STATE_REJECTED_STR,
                                    status.status_code, "");
    }
}

/**************************************************************************//**
 * This function applies an ACL to a given port with a given configuration.
 * This is the create call of PI CRUD API.
 *
 * @param[in] acl_port_map - Pointer to the @see struct acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_cfg_create(struct acl_port_map *acl_port_map, struct port *port,
                        struct ofproto *ofproto)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s - containing port row created",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    /* no new/alloc to perform. Lifetime of acl_port_map is controlled by
       its containing acl_port */

    /* The lag port iface reconfiguration list is NULL here as
       we are applying ACL to the port, that we just created */
    acl_port_map_update_cfg_internal(acl_port_map, port, ofproto, NULL);
}

/**************************************************************************//**
 * This function updates/replaces an ACL to a given port with a given
 * configuration.
 * This is the update/replace call of PI CRUD API.
 *
 * @param[in] acl_port_map - Pointer to the @see struct acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_cfg_update(struct acl_port_map* acl_port_map, struct port *port,
                        struct ofproto *ofproto,
                        struct ovs_list *reconfigure_lag_ifaces_list)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s - containing port row updated",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    acl_port_map_update_cfg_internal(acl_port_map, port, ofproto,
                                     reconfigure_lag_ifaces_list);
}

/**************************************************************************//**
 * This function unapplies an ACL to a given port with a given
 * configuration.
 * This is the delete call of PI CRUD API.
 *
 * @param[in] acl_port_map - Pointer to the @see struct acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_cfg_delete(struct acl_port_map* acl_port_map, struct port *port,
                        struct ofproto *ofproto)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s deleted",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    if (acl_port_map->hw_acl) {
        acl_port_map_unapply_internal(acl_port_map, port, ofproto);
    } else {
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s no PD call needed",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction]);
    }

    /* There's nothing to log to OVSDB for a ACL_PORT_MAP:D, the OVSDB row
     * is already gone. */

    /* We don't release/free the acl_port_map* here. It's owned/managed
       by the acl_port structure. */
}

static void
acl_port_map_stats_get(struct acl_port_map *acl_port_map,
                       struct ofproto *ofproto)
{
    struct ops_cls_interface_info interface_info;

    struct ops_cls_pd_list_status status;
    int num_entries;
    int rc;
    struct ops_cls_statistics *statistics;
    int64_t *key_stats;
    int64_t *val_stats;
    int     num_stat_entries = 0, entry_idx;
    char    status_str[OPS_CLS_STATUS_MSG_MAX_LEN];
    unsigned int sequence_number = 0;

    VLOG_DBG("%s: acl_port_map port: %s, type %u direction %u\n",__FUNCTION__,
              acl_port_map->parent->port->name, acl_port_map->acl_db->type,
              acl_port_map->acl_db->direction);


    /* Check if there is an ACL applied to this port map */
    if (!acl_port_map->hw_acl) {
        VLOG_DBG("No ACL applied for port %s, type %u, direction %u\n",
                 acl_port_map->parent->port->name, acl_port_map->acl_db->type,
                 acl_port_map->acl_db->direction);
        return;
    }

    /* Construct the interface info */
    ops_cls_interface_info_construct(&interface_info, acl_port_map->parent,
                                     acl_port_map->parent->port);
    /* Initialize statistics structure */
    num_entries = acl_port_map->hw_acl->ovsdb_row->n_cur_aces;
    statistics = xzalloc(num_entries *
                         sizeof(struct ops_cls_statistics));


    /* Get stats from ASIC layer */
    rc = call_ofproto_ops_cls_statistics_get(acl_port_map->hw_acl,
                                            acl_port_map->parent->port,
                                            ofproto,
                                            &interface_info,
                                            acl_port_map->acl_db->direction,
                                            statistics,
                                            num_entries,
                                            &status);
    if (rc == 0) {
        /* Initialize results for num_entries
         * although, stats enabled entries might be less than num_entries
         * it should be OK considering max num_entries are going to be 512
         * @todo: considering this function gets called every x seconds
         * we can evaluate if we should allocate these structures one time
         * and use them v/s alloc/free in this fucntion i.e. reserving
         * max required memory in advance v/s fragmentation caused by
         * frequent alloc/free.
         */
        key_stats = xzalloc(num_entries * sizeof(int64_t));
        val_stats = xzalloc(num_entries * sizeof(int64_t));

        /* collect stats */
        for(entry_idx = 0; entry_idx < num_entries; entry_idx++) {
            if(statistics[entry_idx].stats_enabled){
                ovs_assert(entry_idx < acl_port_map->hw_acl->ovsdb_row->n_cur_aces);
                key_stats[num_stat_entries] =
                    acl_port_map->hw_acl->ovsdb_row->key_cur_aces[entry_idx];
                val_stats[num_stat_entries] = statistics[entry_idx].hitcounts;
                num_stat_entries++;
            }
        }

        /* Upload stats to ovsdb */
        acl_db_util_set_statistics(acl_port_map->acl_db,
                                            acl_port_map->parent->ovsdb_row,
                                            key_stats,val_stats,
                                            num_stat_entries);

        /* release memory */
        free(key_stats);
        free(val_stats);

   } else {
        /* Error handling
         * Note: statistics operation error is not required to be logged into
         * db status column
         */

        /* convert entry_id to sequence_number using cur_aces */
        if(status.entry_id < acl_port_map->hw_acl->ovsdb_row->n_cur_aces) {
            sequence_number =
                acl_port_map->hw_acl->ovsdb_row->key_cur_aces[status.entry_id];
        }

        ops_cls_status_msgs_get(status.status_code,
            OPS_CLS_STATUS_MSG_OP_GET_STR,
            OPS_CLS_STATUS_MSG_FEATURE_ACL_STAT_STR,
            OPS_CLS_STATUS_MSG_IFACE_PORT_STR,
            acl_port_map->parent->port->name,
            sequence_number,
            OPS_CLS_STATUS_MSG_MAX_LEN,
            status_str);

        /* since this function gets called every x seconds, logging it as
         * a warning instead of error
         */
        VLOG_WARN(status_str);

    }

    /* free memory allocated for statistics */
    free(statistics);
}

/**************************************************************************//**
 * This function unapplies an ACL to a given port with a given
 * configuration when an ACL is deleted.
 *
 * @param[in] acl_port_map - Pointer to the @see struct acl_port_map
 *****************************************************************************/
static void
acl_port_map_unapply_for_acl_cfg_delete(struct acl_port_map* acl_port_map)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s upapply for ACL delete",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    acl_port_map_cfg_delete(acl_port_map, acl_port_map->parent->port,
                            acl_port_map->parent->port->bridge->ofproto);
}

/**************************************************************************//**
 * Hash map containing all acl_ports
 *****************************************************************************/
static struct shash all_ports = SHASH_INITIALIZER(&all_ports);

struct acl_port *
acl_port_lookup(const char *name)
{
    return ((struct acl_port *)shash_find_data(&all_ports, name));
}

/**************************************************************************//**
 * This function shows all acl_ports in the hash map. Used for debugging.
 * @param[in] conn - Pointer to unixctl connection
 * @param[in] argc - Number of arguments in the command
 * @param[in] argv - Command arguments
 * @param[in] aux  - Aux pointer. Unused for now
 *****************************************************************************/
static void
acl_show_ports(struct unixctl_conn *conn, int argc, const char *argv[],
               void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct shash_node *node, *next;
    struct acl_port *acl_port;

    SHASH_FOR_EACH_SAFE(node, next, &all_ports) {
        acl_port = (struct acl_port *)node->data;
        ds_put_format(&ds, "-----------------------------\n");
        ds_put_format(&ds, "Port name: %s\n", acl_port->port->name);
        if (acl_port->port_map[ACL_CFG_PORT_V4_IN].hw_acl) {
            ds_put_format(&ds, "Applied ACL name: %s\n",
                acl_port->port_map[ACL_CFG_PORT_V4_IN].hw_acl->name);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/**************************************************************************//**
 * This function checks all members of the lag and if atleast one member
 * is up, marks the lag to be active. Only if the LAG is active, a PD
 * call will be made to apply an ACL to this lag.
 *
 * @param[in] acl_port - Pointer to the acl_port of the lag
 *****************************************************************************/
static void
acl_port_check_and_set_active_lag(struct acl_port *acl_port)
{
    bool all_members_inactive = true;
    struct acl_port_interface *iface = NULL;

    if (acl_port == NULL) {
        VLOG_ERR("acl_port cannot be NULL");
        return;
    }

    LIST_FOR_EACH(iface, iface_node, &acl_port->port_ifaces) {
        if (iface->tx_enable && iface->rx_enable) {
            all_members_inactive = false;
            break;
        }
    }
    if (all_members_inactive) {
        acl_port->lag_members_active = false;
    } else {
        acl_port->lag_members_active = true;
    }
}

/**************************************************************************//**
 * This function deletes lag port ifaces list, which needed
 * reconfiguration
 *
 * @param[in] iface_list  - Lag port interfaces list
 *****************************************************************************/
static void
acl_port_lag_iface_reconfigure_list_delete(struct ovs_list *iface_list)
{
    struct acl_port_reconfigure_lag_iface *iface_element      = NULL;
    struct acl_port_reconfigure_lag_iface *iface_element_next = NULL;

    if ((iface_list == NULL) || (list_is_empty(iface_list))) {
        return;
    }

    LIST_FOR_EACH_SAFE(iface_element, iface_element_next, lag_iface_node,
                       iface_list)
    {
        list_remove(&iface_element->lag_iface_node);
        free(iface_element);
    }
}


/**************************************************************************//**
 * This function removes a interface element from a lag port
 * interface list
 *
 * @param[in] iface_element  - interface element to be
 *                             removed
 *****************************************************************************/
static void
acl_port_lag_iface_list_element_remove(
    struct acl_port_interface *iface_element)
{
    if (iface_element == NULL) {
        return;
    }

    list_remove(&iface_element->iface_node);
    free(iface_element);
}


/**************************************************************************//**
 * This function deletes a list of interfaces for a lag port
 * from the acl_port
 *
 * @param[in] iface_list  - port interfaces list
 *****************************************************************************/
static void
acl_port_lag_iface_list_delete(struct ovs_list *iface_list)
{
    struct acl_port_interface *iface_element      = NULL;
    struct acl_port_interface *iface_element_next = NULL;

    if ((iface_list == NULL) || (list_is_empty(iface_list))) {
        return;
    }

    LIST_FOR_EACH_SAFE(iface_element, iface_element_next, iface_node,
                       iface_list)
    {
        acl_port_lag_iface_list_element_remove(iface_element);
    }
}


/**************************************************************************//**
 * This function updates the list of lag port interfaces that
 * need to be reconfigured
 *
 * @param[in]  ofp_port                   - Lag port that needs
 *                                          to be updated
 * @param[in]  action                     - Action to be
 *                                          performed on this
 *                                          lag iface
 * @param[out] reconfgure_lag_iface_list  - Lag port interfaces
 *                                          list
 *****************************************************************************/
static void
acl_port_lag_iface_reconfigure_list_update(
    ofp_port_t ofp_port,
    int action,
    struct ovs_list *reconfigure_iface_list)
{
    if ((reconfigure_iface_list == NULL)) {
        return;
    }

    struct acl_port_reconfigure_lag_iface *iface_element =
            xzalloc(sizeof(struct acl_port_reconfigure_lag_iface));

    iface_element->port_number = ofp_port;
    iface_element->action = action;
    list_push_back(reconfigure_iface_list, &iface_element->lag_iface_node);
}


/**************************************************************************//**
 * This function adds the iface element to a list of interfaces
 * for a lag port
 *
 * @param[in]  iface       - Pointer to @see struct iface
 * @param[out] iface_list  - port interfaces list
 *****************************************************************************/
static void
acl_port_lag_iface_list_element_add(struct acl_port *acl_port,
                                    struct iface       *iface)
{
    if ((acl_port == NULL) || (iface == NULL)) {
        VLOG_ERR("acl_port and iface cannot be NULL");
        return;
    }

    struct acl_port_interface *iface_element =
            xzalloc(sizeof(struct acl_port_interface));

    if (!smap_is_empty(&iface->cfg->hw_bond_config)) {
        iface_element->rx_enable = smap_get_bool(
                         &iface->cfg->hw_bond_config,
                         INTERFACE_HW_BOND_CONFIG_MAP_RX_ENABLED,
                         false);
        iface_element->tx_enable = smap_get_bool(
                         &iface->cfg->hw_bond_config,
                         INTERFACE_HW_BOND_CONFIG_MAP_TX_ENABLED,
                         false);
    }
    else {
        VLOG_DBG("hw_bond_config not set for %s iface", iface->name);
        iface_element->rx_enable = false;
        iface_element->tx_enable = false;
    }

    iface_element->ofp_port = iface->ofp_port;
    list_push_back(&acl_port->port_ifaces, &iface_element->iface_node);
}


/**************************************************************************//**
 * This function creates a list of interfaces for a lag port in
 * the acl_port
 *
 * @param[in]   port        - Pointer to @see struct port
 * @param[out]  iface_list  - port interfaces list
 *****************************************************************************/
static void
acl_port_lag_iface_list_create(struct acl_port     *acl_port)
{
    struct iface *iface = NULL;

    if (acl_port == NULL) {
        VLOG_ERR("acl_port cannot be NULL");
        return;
    }

    LIST_FOR_EACH(iface, port_elem, &acl_port->port->ifaces) {
        acl_port_lag_iface_list_element_add(acl_port, iface);
    }
    acl_port_check_and_set_active_lag(acl_port);
}


/**************************************************************************//**
 * This function checks if the rx and tx states in
 * hw_bond_config changed for the lag port ifaces. If there is a
 * state change for a lag port iface, it updates the
 * reconfiguration lag port ifaces list with the transitioned
 * iface, along with the action to be performed. The new state
 * is copied to the ifaces list maintained in acl_port
 *
 * @param[in]  port                        - Pointer to @see
 *                                           struct port
 * @param[out] acl_port                    - Pointer to @see
 *                                           struct acl_port
 * @param[out] reconfigure_ifaces_list     - list containing
 *                                           lag ports that need
 *                                           reconfiguration
 *****************************************************************************/
static void
acl_port_lag_iface_state_transition_check(
    struct port     *port,
    struct acl_port *acl_port,
    struct ovs_list *reconfigure_ifaces_list)
{
    struct iface *iface = NULL;
    struct acl_port_interface *acl_port_iface = NULL;
    bool port_iface_rx = false;
    bool port_iface_tx = false;

    if ((port == NULL) || (acl_port == NULL) ||
        (reconfigure_ifaces_list == NULL)) {
        return;
    }

    LIST_FOR_EACH(acl_port_iface, iface_node, &acl_port->port_ifaces) {
        LIST_FOR_EACH(iface, port_elem, &port->ifaces) {
            /* If the hw_bond_config value does not exist for this interface,
             * no action needs to be taken. Skip to the next interface.
             */
            if (smap_is_empty(&iface->cfg->hw_bond_config)) {
                continue;
            }

            if (acl_port_iface->ofp_port == iface->ofp_port) {
                port_iface_rx = smap_get_bool(
                         &iface->cfg->hw_bond_config,
                         INTERFACE_HW_BOND_CONFIG_MAP_RX_ENABLED,
                         false);
                port_iface_tx = smap_get_bool(
                         &iface->cfg->hw_bond_config,
                         INTERFACE_HW_BOND_CONFIG_MAP_TX_ENABLED,
                         false);

                if (acl_port_iface->rx_enable && acl_port_iface->tx_enable) {
                    if ((!port_iface_rx) && (!port_iface_tx)) {
                        /* Update the reconfiguration list with iface
                           whose state transitioned */
                        acl_port_lag_iface_reconfigure_list_update(
                                           acl_port_iface->ofp_port,
                                           OPS_CLS_LAG_MEMBER_INTF_DEL,
                                           reconfigure_ifaces_list);
                    }
                }
                else if (!acl_port_iface->rx_enable &&
                         !acl_port_iface->tx_enable) {
                    if ((port_iface_rx) && (port_iface_tx)) {
                        /* Update the reconfiguration list with iface
                           whose state transitioned */
                        acl_port_lag_iface_reconfigure_list_update(
                                           acl_port_iface->ofp_port,
                                           OPS_CLS_LAG_MEMBER_INTF_ADD,
                                           reconfigure_ifaces_list);
                    }
                }

                /* The hw_bond_config state of iface changed.
                 * So update the state of corresponding iface
                 * maintained in the acl_port */
                acl_port_iface->rx_enable = port_iface_rx;
                acl_port_iface->tx_enable = port_iface_tx;
            }
        }
    }
    acl_port_check_and_set_active_lag(acl_port);
}


/**************************************************************************//**
 * This function removes a lag port interface from the internal
 * list (maintained in acl_port). It then updates the lag port
 * interfaces list, that need to be reconfigured, along with the
 * action to be performed on it
 *
 * @param[in]  port                        - Pointer to @see
 *                                           struct port
 * @param[out] acl_port                    - Pointer to @see
 *                                           struct acl_port
 * @param[out] reconfigure_ifaces_list     - list containing
 *                                           lag ports ifaces
 *                                           that need
 *                                           reconfiguration
 *****************************************************************************/
static void
acl_port_lag_iface_list_remove(struct port     *port,
                               struct acl_port *acl_port,
                               struct ovs_list *reconfigure_ifaces_list)
{
    struct iface *iface = NULL;
    struct acl_port_interface *acl_port_iface = NULL;
    bool iface_in_list = false;

    if ((port == NULL) || (acl_port == NULL) ||
        (reconfigure_ifaces_list == NULL)) {
        return;
    }

    LIST_FOR_EACH(acl_port_iface, iface_node, &acl_port->port_ifaces) {
        iface_in_list = false;
        LIST_FOR_EACH(iface, port_elem, &port->ifaces) {
            if (acl_port_iface->ofp_port == iface->ofp_port) {
                iface_in_list = true;
                break;
            }
        }
        if (!iface_in_list) {

            /* Update the reconfiguration list with iface removed if the
             * iface was an active member of the lag */
            if (acl_port_iface->rx_enable && acl_port_iface->tx_enable) {
                acl_port_lag_iface_reconfigure_list_update(
                                               acl_port_iface->ofp_port,
                                               OPS_CLS_LAG_MEMBER_INTF_DEL,
                                               reconfigure_ifaces_list);
            }

            /* An existing iface got removed from this lag port. So remove it
               from the list of ifaces maintained in acl_port, corresponding
               to the lag port */
            acl_port_lag_iface_list_element_remove(acl_port_iface);
        }
    }
    acl_port_check_and_set_active_lag(acl_port);
}


/**************************************************************************//**
 * This function adds a new lag port interface to the internal
 * list (maintained in acl_port). It then updates the lag port
 * interfaces list that need to be reconfigured, along with the
 * action to be performed on it
 *
 * @param[in]  port                        - Pointer to @see
 *                                           struct port
 * @param[out] acl_port                    - Pointer to @see
 *                                           struct acl_port
 * @param[out] reconfigure_ifaces_list     - list containing
 *                                           lag port ifaces
 *                                           that need
 *                                           reconfiguration
 *****************************************************************************/
static void
acl_port_lag_iface_list_add(struct port     *port,
                            struct acl_port *acl_port,
                            struct ovs_list *reconfigure_ifaces_list)
{
    struct iface *iface = NULL;
    struct acl_port_interface *acl_port_iface = NULL;
    bool iface_in_list = false;

    if ((port == NULL) || (acl_port == NULL) ||
        (reconfigure_ifaces_list == NULL)) {
        VLOG_ERR("port, acl_port and reconfigure_ifaces_list cannot be NULL");
        return;
    }

    LIST_FOR_EACH(iface, port_elem, &port->ifaces) {
        iface_in_list = false;
        LIST_FOR_EACH(acl_port_iface, iface_node, &acl_port->port_ifaces) {
            if (iface->ofp_port == acl_port_iface->ofp_port) {
                iface_in_list = true;
                break;
            }
        }
        if (!iface_in_list) {
            /* A new iface got added to this lag port. So add it to the
               the list of ifaces maintained in acl_port corresponding
               to this lag port */
            acl_port_lag_iface_list_element_add(acl_port, iface);

            /* Update the reconfiguration list with this new iface if
             * the interface is enabled */
            if (acl_port_iface->rx_enable && acl_port_iface->tx_enable) {
                acl_port_lag_iface_reconfigure_list_update(
                                  iface->ofp_port,
                                  OPS_CLS_LAG_MEMBER_INTF_ADD,
                                  reconfigure_ifaces_list);
            }
        }
    }
    acl_port_check_and_set_active_lag(acl_port);
}



/**************************************************************************//**
 * This function checks if the lag port ifaces needs to be
 * reconfigured, either based on changes to current lag port
 * ifaces (Add/Remove) list or based on hw_bond_config state
 * transition. All the lag port ifaces that need
 * reconfiguration are populated in the reconfiguration list
 *
 * @param[in]  port                        - Pointer to @see
 *                                           struct port
 * @param[out]  acl_port                   - Pointer to @see
 *                                           struct acl_port
 * @param[out] reconfigure_ifaces_list     - list containing
 *                                           lag ports that need
 *                                           reconfiguration
 *****************************************************************************/
static void
acl_port_lag_iface_reconfigure_list_build(
    struct port        *port,
    struct acl_port    *acl_port,
    struct ovs_list    *reconfigure_ifaces_list)
{

    if ((port == NULL) || (acl_port == NULL) ||
        (reconfigure_ifaces_list == NULL)) {
        return;
    }

    if ((list_size(&acl_port->port_ifaces) == 0) &&
        (list_size(&port->ifaces) == 0)) {
        return;
    }

    if (list_size(&acl_port->port_ifaces) == list_size(&port->ifaces)) {
        /* NOTE: Here two cases are possible as listed below */

        /* iface are same so check if the hw_bond_config state
           transition happened */
        acl_port_lag_iface_state_transition_check(port, acl_port,
                                                  reconfigure_ifaces_list);
        acl_port_check_and_set_active_lag(acl_port);

        if (list_size(reconfigure_ifaces_list) == 0) {
            /* There are no state transitions. So if any new ifaces
               got added and existing ifaces got removed, update the
               reconfiguration iface list accordingly */
            acl_port_lag_iface_list_add(port, acl_port,
                                       reconfigure_ifaces_list);

            acl_port_lag_iface_list_remove(port, acl_port,
                                       reconfigure_ifaces_list);
        }
    }
    else if (list_size(&port->ifaces) > list_size(&acl_port->port_ifaces)) {
        acl_port_lag_iface_list_add(port, acl_port,
                                    reconfigure_ifaces_list);
    } else {
        acl_port_lag_iface_list_remove(port, acl_port,
                                       reconfigure_ifaces_list);
    }
}


/**************************************************************************//**
 * This function processes the lag ifaces reconfiguration. It
 * builds the list of ifaces that need reconfiguration and calls
 * the function to perform the necessary action
 *
 * @param[in] port         - Pointer to @see struct port
 * @param[in] acl_port     - Pointer to @see struct acl_port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_lag_ifaces_process_reconfiguration(struct port     * port,
                                            struct acl_port * acl_port,
                                            struct ofproto  * ofproto)
{
    struct ovs_list reconfigure_ifaces_list;

    if ((port == NULL) || (acl_port == NULL) || (ofproto == NULL)) {
        return;
    }

    list_init(&reconfigure_ifaces_list);

    /* Build the list of lag port ifaces that need to
       be reconfigured in PD */
    acl_port_lag_iface_reconfigure_list_build(port,
                                              acl_port,
                                              &reconfigure_ifaces_list);

    VLOG_DBG("Number of lag ifaces to reconfigure: %zu \n",
              list_size(&reconfigure_ifaces_list));

    for (int i = ACL_CFG_MIN_PORT_TYPES; i <= ACL_CFG_MAX_PORT_TYPES; i++) {
        if (acl_db_util_get_cfg(&acl_db_accessor[i], port->cfg)) {
            acl_port_map_cfg_update(&acl_port->port_map[i], port,
                                    ofproto,
                                    &reconfigure_ifaces_list);
        }
    }

    acl_port_lag_iface_reconfigure_list_delete(&reconfigure_ifaces_list);
}


/**************************************************************************//**
 * This function checks if any ifaces within a lag port, are
 * modified. If yes, it processes the lag port reconfiguration
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 * @param[in] br         - Pointer to @see struct bridge
 *****************************************************************************/
static void
acl_port_lag_ifaces_reconfigure_bridge(struct blk_params *blk_params,
                                       struct bridge *br)
{
    struct port *port = NULL;
    struct acl_port *acl_port = NULL;
    struct iface *iface = NULL;
    bool port_iface_modified = false;

    if ((blk_params == NULL) || (br == NULL)) {
        return;
    }

    HMAP_FOR_EACH(port, hmap_node, &br->ports) {
        if (strncmp(port->name, "lag", 3) == 0) {
            acl_port = acl_port_lookup(port->name);
            if (acl_port == NULL) {
                continue;
            }
            LIST_FOR_EACH(iface, port_elem, &port->ifaces) {
                if (OVSREC_IDL_IS_ROW_MODIFIED(iface->cfg,
                                               blk_params->idl_seqno)) {
                    port_iface_modified = true;
                    break;
                }
            }

            /* Call the function that processes the modification
               in lag iface column */
            if (port_iface_modified) {
                acl_port_lag_ifaces_process_reconfiguration(port, acl_port,
                                                    br->ofproto);
            }
        }
    }
}


/**************************************************************************//**
 * Reconfigure function for lag port reconfigure operation. This
 * function is called from reconfigure_init callback, when @see
 * bridge_reconfigure() is called from switchd. This function
 * will look for all lag port ifaces that are modified and
 * reconfigure ACL on such ifaces
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 *****************************************************************************/
void
acl_port_lag_ifaces_reconfigure(struct blk_params *blk_params)
{
    struct bridge *br = NULL;
    struct vrf *vrf = NULL;

    if (blk_params == NULL) {
        return;
    }

    HMAP_FOR_EACH(br, node, blk_params->all_bridges) {
        if (br->ofproto == NULL) {
            continue;
        }
        acl_port_lag_ifaces_reconfigure_bridge(blk_params, br);
    }

    HMAP_FOR_EACH(vrf, node, blk_params->all_vrfs) {
        if ((vrf->up == NULL) || (vrf->up->ofproto == NULL)) {
            continue;
        }
        acl_port_lag_ifaces_reconfigure_bridge(blk_params, vrf->up);
    }
}


/**************************************************************************//**
 * This function creates an acl_port when the port is seen for the first time
 * by ACL feature plugin. This function sets up all possible acl-port
 * configuration types as defined in @see acl_db_accessor global array.
 * Also, it adds thew newly created acl_port into all_ports shash for
 * quick lookup.
 *
 * @param[in] port       - Pointer to @see struct port
 * @param[in] seqno      - idl_seqno of the current idl batch
 * @param[in] interface_flags - Interface flags to specify the type of port
 *
 * @returns Pointer to acl_port
 *****************************************************************************/
static struct acl_port*
acl_port_new(struct port *port, unsigned int seqno,
             unsigned int interface_flags)
{
    struct acl_port *acl_port = xzalloc(sizeof *acl_port);

    /* setup my port_map to know about me and which acl_port_map they represent */
    for (int i = ACL_CFG_MIN_PORT_TYPES; i <= ACL_CFG_MAX_PORT_TYPES; ++i) {
        acl_port_map_construct(&acl_port->port_map[i], acl_port, i);
    }

    acl_port->port = port;
    acl_port->interface_flags |= interface_flags;
    acl_port->ovsdb_row = port->cfg;
    acl_port->delete_seqno = seqno;
    acl_port->lag_members_active = false;

    list_init(&acl_port->port_ifaces);

    /* Create iface list for lag ports */
    if (list_size(&port->ifaces) > 0) {
        acl_port_lag_iface_list_create(acl_port);
    }

    shash_add_assert(&all_ports, port->name, acl_port);
    return acl_port;
}

/**************************************************************************//**
 * This function deletes an acl_port when a delete port is requested.
 * It frees up all memory consumed by the port and removes shash membership.
 *
 * @param[in] acl_port - Port to be deleted
 *****************************************************************************/
static void
acl_port_delete(const char *port_name)
{
    struct acl_port *port = shash_find_and_delete_assert(&all_ports,
                                                         port_name);

    /* cleanup my port_map */
    for (int i = ACL_CFG_MIN_PORT_TYPES; i <= ACL_CFG_MAX_PORT_TYPES; ++i) {
        acl_port_map_destruct(&port->port_map[i]);
    }

    /* cleanup port interfaces list */
    acl_port_lag_iface_list_delete(&port->port_ifaces);

    free(port);
}

void acl_callback_port_delete(struct blk_params *blk_params)
{
    /* Handle port deletes here */
    bool have_ports = !shash_is_empty(&all_ports);
    struct acl_port *acl_port;
    struct bridge *br;
    struct port *del_port, *next_del_port;
    struct ovsrec_port *port_cfg;

    if (!have_ports) {
        VLOG_DBG("[%s]No ports to delete", ACL_PLUGIN_NAME);
        return;
    }

    /* Find the list of ports to operate on. Only one out of bridge and vrf
     * is populated at any given point
     */
    if (blk_params->br) {
        br = blk_params->br;
    } else {
        br = blk_params->vrf->up;
    }

    /* Find and delete ACL cfg for the ports that are being deleted */
    HMAP_FOR_EACH_SAFE(del_port, next_del_port, hmap_node, &br->ports) {
        acl_port = acl_port_lookup(del_port->name);
        if (acl_port == NULL) {
            continue;
        }
        port_cfg = shash_find_data(&br->wanted_ports, del_port->name);
        if (port_cfg == NULL) {
            for (int i = ACL_CFG_MIN_PORT_TYPES;
                 i <= ACL_CFG_MAX_PORT_TYPES; ++i) {
                VLOG_DBG("PORT %s deleted", del_port->name);
                acl_port_map_cfg_delete(&acl_port->port_map[i], del_port, blk_params->ofproto);
            }
            acl_port_delete(del_port->name);
        }
        else {
            if ((strncmp(del_port->name, "lag", 3) == 0) &&
                (port_cfg->n_interfaces == 0))
            {
                /* This indicates that last interface in lag port
                   is getting deleted */

                struct ovs_list reconfigure_ifaces_list;
                struct acl_port_interface *acl_port_iface = NULL;

                list_init(&reconfigure_ifaces_list);

                LIST_FOR_EACH(acl_port_iface, iface_node,
                              &acl_port->port_ifaces) {

                    /* Update the reconfiguration list with iface removed */
                    acl_port_lag_iface_reconfigure_list_update(
                                                acl_port_iface->ofp_port,
                                                OPS_CLS_LAG_MEMBER_INTF_DEL,
                                                &reconfigure_ifaces_list);
                }

                VLOG_DBG("Number of lag ifaces to reconfigure: %zu \n",
                             list_size(&reconfigure_ifaces_list));

                for (int i = ACL_CFG_MIN_PORT_TYPES;
                         i <= ACL_CFG_MAX_PORT_TYPES; i++) {
                    if (acl_db_util_get_cfg(&acl_db_accessor[i],
                                            del_port->cfg)) {
                        acl_port_map_cfg_update(&acl_port->port_map[i],
                                                del_port,
                                                blk_params->ofproto,
                                                &reconfigure_ifaces_list);
                        acl_port_map_set_hw_acl(&acl_port->port_map[i], NULL);
                    }
                }

                acl_port_delete(del_port->name);

                acl_port_lag_iface_reconfigure_list_delete(
                                               &reconfigure_ifaces_list);
            }
        }
    }
}

void
acl_port_unapply_if_needed(struct acl *acl)
{
    struct acl_port_map *port, *next = NULL;

    if (list_is_empty(&acl->acl_port_map)) {
        return;
    }

    LIST_FOR_EACH_SAFE(port, next, acl_node, &acl->acl_port_map) {
        acl_port_map_unapply_for_acl_cfg_delete(port);
    }
}

void acl_callback_port_reconfigure(struct blk_params *blk_params)
{
    struct acl_port            *acl_port;
    struct port                *port = NULL;
    struct bridge              *br;

    /* Find the bridge to work with */
    if (blk_params->br) {
        br = blk_params->br;
    } else {
        br = blk_params->vrf->up;
    }

    /* Port modify routine */
    HMAP_FOR_EACH(port, hmap_node, &br->ports) {
        if (OVSREC_IDL_IS_ROW_MODIFIED(port->cfg, blk_params->idl_seqno)) {
            acl_port = acl_port_lookup(port->name);
            if (acl_port) {
                struct ovs_list reconfigure_ifaces_list;

                list_init(&reconfigure_ifaces_list);

                /* In case of a lag port, need to check if any ifaces were
                   moved out of it. For example, if the lag port has an
                   ACL applied and one of the ifaces is no longer part of
                   the lag port, then ACL needs to be unapplied to that
                   iface*/
                if (strncmp(port->name, "lag", 3) == 0) {
                    acl_port_lag_iface_reconfigure_list_build(
                                               port,
                                               acl_port,
                                               &reconfigure_ifaces_list);

                    VLOG_DBG("Number of lag ifaces to reconfigure: %zu \n",
                             list_size(&reconfigure_ifaces_list));
                }
                for (int i = ACL_CFG_MIN_PORT_TYPES;
                         i <= ACL_CFG_MAX_PORT_TYPES; i++) {
                    if (acl_db_util_get_cfg(&acl_db_accessor[i], port->cfg)) {
                        /* Reconfigure ACL */
                        acl_port->ovsdb_row = port->cfg;
                        acl_port->delete_seqno = blk_params->idl_seqno;
                        VLOG_DBG("PORT %s changed", acl_port->port->name);
                        acl_port_map_cfg_update(&acl_port->port_map[i], port,
                                                blk_params->ofproto,
                                                &reconfigure_ifaces_list);
                    } else {
                        /* If the port row modification was unapply ACL, then
                         * this case is hit.
                         */
                         VLOG_DBG("PORT %s deleted", port->name);
                         acl_port_map_cfg_delete(&acl_port->port_map[i], port,
                                                 blk_params->ofproto);
                    }
                }
                acl_port_lag_iface_reconfigure_list_delete(
                                               &reconfigure_ifaces_list);
            }
        }
    }
}

void
acl_callback_port_update(struct blk_params *blk_params)
{
    struct acl_port *acl_port;
    unsigned int interface_flags = 0;

    VLOG_DBG("Port Update called for %s\n", blk_params->port->name);

    acl_port = acl_port_lookup(blk_params->port->name);

    if (!acl_port) {
        if (blk_params->vrf) {
            interface_flags |= OPS_CLS_INTERFACE_L3ONLY;
        }

        /* Create on the port.*/
        struct acl_port *acl_port = acl_port_new(blk_params->port,
                                                 blk_params->idl_seqno,
                                                 interface_flags);
        VLOG_DBG("PORT %s created", blk_params->port->cfg->name);

        /* Apply if ACL is configured on the port.*/
        for (int i = ACL_CFG_MIN_PORT_TYPES; i <= ACL_CFG_MAX_PORT_TYPES; ++i) {
            if (acl_db_util_get_cfg(&acl_db_accessor[i], blk_params->port->cfg)) {
                 acl_port_map_cfg_create(&acl_port->port_map[i],
                                          blk_params->port,
                                          blk_params->ofproto);
            }
        }
    }
    else {
        /* check if it is a lag port */
        if (strncmp(blk_params->port->name, "lag", 3) == 0) {
            acl_port_lag_ifaces_process_reconfiguration(blk_params->port, acl_port,
                                                        blk_params->ofproto);
        }
    }
}

void
acl_callback_port_stats_get(struct stats_blk_params *sblk,
                            enum stats_block_id blk_id)
{
    struct bridge *br;
    struct acl_port *acl_port;

    /* Get the bridge to work with */
    if (blk_id == STATS_PER_BRIDGE_PORT) {
        br = sblk->br;
    } else {
        br = sblk->vrf->up;
    }

    /* Get the ACL port based on given port */
    acl_port = acl_port_lookup(sblk->port->name);
    if (!acl_port) {
        VLOG_DBG("Stats get not needed for port %s\n", sblk->port->name);
        return;
    }
    /* Get statistics for this port if needed */
    for (int i = ACL_CFG_MIN_PORT_TYPES; i <= ACL_CFG_MAX_PORT_TYPES; ++i) {
        acl_port_map_stats_get(&acl_port->port_map[i], br->ofproto);
    }
}

void
acl_port_debug_init()
{
    /* Dump acl_port shash */
    unixctl_command_register("acl_plugin/show_port", NULL, 0, 1,
                             acl_show_ports, NULL);
}
