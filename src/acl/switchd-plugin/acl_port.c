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
#include "openvswitch/vlog.h"
#include "reconfigure-blocks.h"
#include "acl_plugin.h"
#include "acl_ofproto.h"
#include "ops_cls_status_msgs.h"


VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin_port);

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
                                 const struct acl_port *acl_port OVS_UNUSED,
                                 const struct port* port OVS_UNUSED)
{
    memset(interface_info, 0, sizeof *interface_info);

    /* TODO: handle more interface types when we know how to */
    interface_info->interface = OPS_CLS_INTERFACE_PORT;
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
    struct smap cfg_status;
    char code_str[10];
    //char version[25];

    smap_clone(&cfg_status, &row->aclv4_in_status);

    /* Remove any values that exist */
    smap_remove(&cfg_status, OPS_CLS_STATUS_VERSION_STR);
    smap_remove(&cfg_status, OPS_CLS_STATUS_STATE_STR);
    smap_remove(&cfg_status, OPS_CLS_STATUS_CODE_STR);
    smap_remove(&cfg_status, OPS_CLS_STATUS_MSG_STR);

    /* Add values to the smap */
    /*
     * TODO: Uncomment this code when UI fills version field
     *
     * sprintf(version, "%" PRId64"", row->aclv4_in_cfg_version[0]);
     * smap_add(&cfg_status, OPS_CLS_STATUS_VERSION_STR,
     *          version);
     */
    smap_add(&cfg_status, OPS_CLS_STATUS_STATE_STR, state);
    sprintf(code_str, "%u", code);
    smap_add(&cfg_status, OPS_CLS_STATUS_CODE_STR, code_str);
    smap_add(&cfg_status, OPS_CLS_STATUS_MSG_STR, details);

    /* Write cfg_status column */
    acl_db_util_set_cfg_status(acl_port_map->acl_db, row, &cfg_status);
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
                                 struct port *port, struct ofproto *ofproto)
{
    struct ops_cls_pd_status status;
    memset(&status, 0, sizeof status);
    struct ops_cls_interface_info interface_info;
    ops_cls_interface_info_construct(&interface_info,
                                     acl_port_map->parent, port);
    int rc;
    const char *method_called = NULL;
    /* details is used to log message in VLOG */
    char details[256];
    /* status_str used to store status description in db */
    char status_str[OPS_CLS_STATUS_MSG_MAX_LEN] = {0};
    unsigned int sequence_number = 0;

    struct acl* acl;
    /* TODO: Start looking at want_version too.
     *       Short circuit if want_version == want_status_version.
     */
    const struct ovsrec_acl *ovsdb_acl =
        acl_db_util_get_cfg(acl_port_map->acl_db, acl_port_map->parent->ovsdb_row);
    if (!ovsdb_acl) {
        acl = NULL;
        if (acl_port_map->hw_acl) {
            rc = call_ofproto_ops_cls_remove(acl_port_map->hw_acl,
                                             port,
                                             ofproto,
                                             &interface_info,
                                             acl_port_map->acl_db->direction,
                                             &status);
            method_called =  OPS_CLS_STATUS_MSG_OP_REMOVE_STR;
        } else {
            /* Nothing to delete in PD for this ACL_PORT_MAP */
        }
    } else {
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
            /* Nothing to update in PD for this ACL_PORT_MAP */
        } else if (!acl_port_map->hw_acl) {
            VLOG_DBG("ACL_PORT_MAP %s:%s:%s applying %s",
                     acl_port_map->parent->name,
                     ops_cls_type_strings[acl_port_map->acl_db->type],
                     ops_cls_direction_strings[acl_port_map->acl_db->direction],
                     acl->name);
            rc = call_ofproto_ops_cls_apply(acl,
                                            port,
                                            ofproto,
                                            &interface_info,
                                            acl_port_map->acl_db->direction,
                                            &status);
            method_called = OPS_CLS_STATUS_MSG_OP_APPLY_STR;
        } else {
            VLOG_DBG("ACL_PORT_MAP %s:%s:%s replacing %s with %s",
                     acl_port_map->parent->name,
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
    }

    if (method_called == NULL) {
        sprintf(details, "ACL_PORT_MAP %s:%s:%s no PD call needed",
                 acl_port_map->parent->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction]);
        VLOG_DBG(details);
        /* status_str will be NULL on success */
        acl_port_map_set_cfg_status(acl_port_map, port->cfg,
                            OPS_CLS_STATE_APPLIED_STR, 0, status_str);
    } else if (rc == 0) {
        /* success */
        sprintf(details, "ACL_PORT_MAP %s:%s:%s -- PD %s succeeded",
                 acl_port_map->parent->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction],
                 method_called);
        VLOG_DBG(details);
        acl_port_map_set_hw_acl(acl_port_map, acl);
        acl_db_util_set_applied(acl_port_map->acl_db, port->cfg,
                                 acl->ovsdb_row);
        /* status_str will be NULL on success */
        acl_port_map_set_cfg_status(acl_port_map, port->cfg,
                                    OPS_CLS_STATE_APPLIED_STR,
                                    status.status_code, status_str);
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
                                acl_port_map->parent->name,
                                sequence_number,
                                OPS_CLS_STATUS_MSG_MAX_LEN,
                                status_str);
        sprintf(details, "ACL_PORT_MAP %s:%s:%s -- PD %s failed",
                 acl_port_map->parent->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction],
                 method_called);
        VLOG_DBG(details);
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
             acl_port_map->parent->name,
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
             acl_port_map->parent->name,
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
             acl_port_map->parent->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    /* no new/alloc to perform. Lifetime of acl_port_map is controlled by
       its containing acl_port */

    /* TODO: Remove temporary processing of ACL_PORT_MAP:C like an ACL_PORT_MAP:U */
    acl_port_map_update_cfg_internal(acl_port_map, port, ofproto);
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
                        struct ofproto *ofproto)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s - containing port row updated",
             acl_port_map->parent->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    acl_port_map_update_cfg_internal(acl_port_map, port, ofproto);
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
             acl_port_map->parent->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    if (acl_port_map->hw_acl) {
        acl_port_map_unapply_internal(acl_port_map, port, ofproto);
    } else {
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s no PD call needed",
                 acl_port_map->parent->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction]);
    }

    /* There's nothing to log to OVSDB for a ACL_PORT_MAP:D, the OVSDB row
     * is already gone. */

    /* We don't release/free the acl_port_map* here. It's owned/managed
       by the acl_port structure. */
}

/** TODO: Enable this block after list delete is implemented */
#if 0
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
             acl_port_map->parent->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

/*    struct port *port = global_port_lookup(acl_port_map->parent->name);
    if (!port) {
        VLOG_ERR("INTERNAL ERROR: PORT %s not found. Unable to unapply acl_port_map",
                 acl_port_map->parent->name);
        return;
    }

    acl_port_map_unapply_internal(acl_port_map, port);
*/
    /* TODO: We must update OVSDB
     *       _applied must go to NULL
     *       _cfg_status must change too
     *         failed w/ reason = ACL deleted while applied
     */
}
#endif

/**************************************************************************//**
 * Hash map containing all acl_ports
 *****************************************************************************/
static struct hmap all_ports = HMAP_INITIALIZER(&all_ports);

/**************************************************************************//**
 * This function looks up an acl_port based on UUID of a port row
 *
 * @param[in] uuid   - Pointer to @see struct uuid
 *
 * @returns  Pointer to acl_port if found
 *           NULL otherwise
 *****************************************************************************/
static struct acl_port *
port_lookup(const struct uuid* uuid)
{
    struct acl_port *port;

    HMAP_FOR_EACH_WITH_HASH(port, all_node_uuid, uuid_hash(uuid),
                            &all_ports) {
        if (uuid_equals(&port->uuid, uuid)) {
            return port;
        }
    }
    return NULL;
}

/**************************************************************************//**
 * This function creates an acl_port when the port is seen for the first time
 * by ACL feature plugin. This function sets up all possible acl-port
 * configuration types as defined in @see acl_db_accessor global array.
 * Also, it adds thew newly created acl_port into all_ports hashmap for
 * quick lookup.
 *
 * @param[in] ovsdb_row  - Pointer to the ovsdb port row
 * @param[in] seqno      - idl_seqno of the current idl batch
 *
 * @returns Pointer to acl_port
 *****************************************************************************/
static struct acl_port*
acl_port_new(const struct ovsrec_port *ovsdb_row, unsigned int seqno)
{
    struct acl_port *port = xzalloc(sizeof *port);
    port->uuid = ovsdb_row->header_.uuid;
    port->name = xstrdup(ovsdb_row->name); /* we can outlive ovsdb_row */

    /* setup my port_map to know about me and which colgrp they represent */
    for (int i = 0; i < NUM_ACL_CFG_TYPES; ++i) {
        acl_port_map_construct(&port->port_map[i], port, i);
    }

    port->ovsdb_row = ovsdb_row;
    port->delete_seqno = seqno;
    hmap_insert(&all_ports, &port->all_node_uuid, uuid_hash(&port->uuid));
    return port;
}

/**************************************************************************//**
 * This function deletes an acl_port when a delete port is requested.
 * It frees up all memory consumed by the port and removes hashmap membership.
 *
 * @param[in] acl_port - Port to be deleted
 *****************************************************************************/
static void
acl_port_delete(struct acl_port* acl_port)
{
    if (acl_port) {
        hmap_remove(&all_ports, &acl_port->all_node_uuid);
        free(CONST_CAST(char *, acl_port->name));

        /* cleanup my port_map */
        for (int i = 0; i < NUM_ACL_CFG_TYPES; ++i) {
            acl_port_map_destruct(&acl_port->port_map[i]);
        }

        free(acl_port);
    }
}

/**************************************************************************//**
 * This function wraps @see acl_port_new() and @see acl_port_map_cfg_create()
 * functions. It is called when the port is seen first time in ACL feature
 * plugin
 *
 * @param[in] port         - Pointer to @see struct port
 * @param[in] seqno        - idl_seqno of the current idl batch
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *
 * @returns Pointer to the newly created and configured acl_port
 *****************************************************************************/
static struct acl_port*
acl_port_cfg_create(struct port *port, unsigned int seqno,
                    struct ofproto *ofproto)
{
    VLOG_DBG("PORT %s created", port->cfg->name);
    struct acl_port *acl_port = acl_port_new(port->cfg, seqno);

    for (int i = 0; i < NUM_ACL_CFG_TYPES; ++i) {
        acl_port_map_cfg_create(&acl_port->port_map[i], port, ofproto);
    }

    return acl_port;
}

/**************************************************************************//**
 * This function wraps @see acl_port_map_cfg_update() function. It is called
 * when the port row is updated with new ACL value
 *
 * @param[in] acl_port     - Pointer to @see struct acl_port
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_cfg_update(struct acl_port *acl_port, struct port *port,
                    struct ofproto *ofproto)
{
    VLOG_DBG("PORT %s changed", acl_port->name);
    /* TODO: rework this when we have the full
       Change/Transaction structure */
    /* Defer PD update to P2ACL structs */
    for (int i = 0; i < NUM_ACL_CFG_TYPES; ++i) {
        acl_port_map_cfg_update(&acl_port->port_map[i], port, ofproto);
    }
}

/**************************************************************************//**
 * This function wraps @see acl_port_map_cfg_delete() function. It is called
 * when the port row is deleted.
 *
 * @param[in] acl_port     - Pointer to @see struct acl_port
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_cfg_delete(struct acl_port* acl_port, struct port *port,
                    struct ofproto *ofproto)
{
    VLOG_DBG("PORT %s deleted", port->name);
    for (int i = 0; i < NUM_ACL_CFG_TYPES; ++i) {
        acl_port_map_cfg_delete(&acl_port->port_map[i], port, ofproto);
    }
}

void acl_callback_port_delete(struct blk_params *blk_params)
{
    /* Handle port deletes here */
    bool have_ports = !hmap_is_empty(&all_ports);
    struct acl_port *acl_port;
    struct bridge *br;
    struct port *del_port, *next_del_port;

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
        if (!shash_find_data(&br->wanted_ports, del_port->name)) {
            acl_port = port_lookup(&del_port->cfg->header_.uuid);
            if (acl_port) {
                acl_port_cfg_delete(acl_port, del_port, blk_params->ofproto);
                acl_port_delete(acl_port);
            }
        }
    }
}

void acl_callback_port_reconfigure(struct blk_params *blk_params)
{
    struct acl_port *acl_port;
    struct port *port = NULL;
    struct bridge *br;

    /* Find the bridge to work with */
    if (blk_params->br) {
        br = blk_params->br;
    } else {
        br = blk_params->vrf->up;
    }

    /* Port modify routine */
    HMAP_FOR_EACH(port, hmap_node, &br->ports) {
        if (OVSREC_IDL_IS_ROW_MODIFIED(port->cfg, blk_params->idl_seqno)) {
            acl_port = port_lookup(&port->cfg->header_.uuid);
            if (acl_port) {
                if (port->cfg->aclv4_in_cfg) {
                    /* Reconfigure ACL */
                    acl_port->ovsdb_row = port->cfg;
                    acl_port->delete_seqno = blk_params->idl_seqno;
                    acl_port_cfg_update(acl_port, port, blk_params->ofproto);
                } else {
                    /* If the port row modification was unapply ACL, then
                     * this case is hit.
                     */
                    acl_port_cfg_delete(acl_port, port, blk_params->ofproto);
                }
            }
        }
    }
}

void
acl_callback_port_update(struct blk_params *blk_params)
{
    struct acl_port *acl_port;

    VLOG_DBG("Port Update called for %s\n", blk_params->port->name);

    acl_port = port_lookup(&blk_params->port->cfg->header_.uuid);
    if (!acl_port) {
        /* Create and apply if ACL is configured on the port.*/
        if (blk_params->port->cfg->aclv4_in_cfg) {
            acl_port_cfg_create(blk_params->port, blk_params->idl_seqno,
                                blk_params->ofproto);
        } else {
            /* We still create a port entry. However, it will not be programmed
             * until we have an ACL applied to it
             */
             acl_port_new(blk_params->port->cfg, blk_params->idl_seqno);
        }
    }
}
