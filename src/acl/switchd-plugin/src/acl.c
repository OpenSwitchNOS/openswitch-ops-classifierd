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

#include "acl.h"
#include "sort.h"
#include "smap.h"
#include "json.h"
#include "vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ofproto/ofproto-provider.h"
#include "ofproto-ops-classifier.h"
#include "acl_parse.h"
#include "acl_ofproto.h"
#include "p2acl.h"
#include "reconfigure-blocks.h"
#include "acl_plugin.h"

VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin_global);

/* TODO: Remove these once new schema parser is generating them */
#ifndef ACE_KEY_
#define ACE_KEY_
#define ACE_KEY_ACTION                    "action"
#define ACE_KEY_IP_PROTOCOL               "protocol"
#define ACE_KEY_SOURCE_IP_ADDRESS         "src_ip"
#define ACE_KEY_SOURCE_PORT_OPERATOR      "src_l4_op"
#define ACE_KEY_SOURCE_PORT               "src_l4_port"
#define ACE_KEY_SOURCE_PORT_MAX           "src_l4_port_max"
#define ACE_KEY_DESTINATION_IP_ADDRESS    "dst_ip"
#define ACE_KEY_DESTINATION_PORT_OPERATOR "dst_l4_op"
#define ACE_KEY_DESTINATION_PORT          "dst_l4_port"
#define ACE_KEY_DESTINATION_PORT_MAX      "dst_l4_port_max"
#endif

#define ACL_CFG_STATUS_STR     "status_string"
#define ACL_CFG_STATUS_VERSION "version"
#define ACL_CFG_STATUS_STATE   "state"
#define ACL_CFG_STATUS_CODE    "code"
#define ACL_CFG_STATUS_MSG     "message"
#define ACL_CFG_STATE_APPLIED  "applied"
#define ACL_CFG_STATE_REJECTED "rejected"
#define ACL_CFG_STATE_IN_PROGRESS "in_progress"
#define ACL_CFG_STATE_CANCELLED   "cancelled"

struct db_ace {
    uint32_t sequence_number;
    struct ovsrec_acl_entry *acl_entry;
};

static int
sort_compare_aces(size_t a, size_t b, void *aces_)
{
    const struct db_ace *aces = aces_;
    uint32_t a_seq = aces[a].sequence_number;
    uint32_t b_seq = aces[b].sequence_number;

    return (a_seq < b_seq) ? -1 : (a_seq > b_seq);
}

static void
sort_swap_aces(size_t a, size_t b, void *ptrs_)
{
    struct db_ace *ptrs = ptrs_;
    struct db_ace tmp = ptrs[a];
    ptrs[a] = ptrs[b];
    ptrs[b] = tmp;
}
#if 0
static bool
populate_entry_from_json_string(struct ops_cls_list_entry *entry,
                                const char *json_str)
{
    bool valid = true;
    struct json *jsonace = json_from_string(json_str);
    struct shash *ace = json_object(jsonace);

    /* TODO: support more than ipv4 */

    struct shash_node *elem;
    SHASH_FOR_EACH (elem, ace) {
        const char *name = elem->name;
        const char *val  = json_string(elem->data);
        if (strcmp(name, ACE_KEY_SOURCE_IP_ADDRESS)==0) {
            if (!acl_parse_ipv4_address
                (val,
                 OPS_CLS_SRC_IPADDR_VALID,
                 &entry->entry_fields.entry_flags,
                 &entry->entry_fields.src_ip_address.v4,
                 &entry->entry_fields.src_ip_address_mask.v4,
                 &entry->entry_fields.src_addr_family)) {
                VLOG_ERR("invalid source ip addr %s", val);
                valid = false;
            }
        } else if (strcmp(name, ACE_KEY_DESTINATION_IP_ADDRESS)==0) {
            if (!acl_parse_ipv4_address
                (val,
                 OPS_CLS_DEST_IPADDR_VALID,
                 &entry->entry_fields.entry_flags,
                 &entry->entry_fields.dst_ip_address.v4,
                 &entry->entry_fields.dst_ip_address_mask.v4,
                 &entry->entry_fields.dst_addr_family)) {
                VLOG_ERR("invalid destination ip addr %s", val);
                valid = false;
            }
        } else if (strcmp(name, ACE_KEY_IP_PROTOCOL)==0) {
            if (!acl_parse_protocol(val,
                                    OPS_CLS_PROTOCOL_VALID,
                                    &entry->entry_fields.entry_flags,
                                    &entry->entry_fields.protocol)) {
                VLOG_ERR("invalid protocol %s", val);
                valid = false;
            }
        } else if (strcmp(name, ACE_KEY_ACTION)==0) {
            if (!acl_parse_actions(val,
                                   &entry->entry_actions)) {
                VLOG_ERR("invalid action %s", val);
                valid = false;
            }
        } else if (strcmp(name, ACE_KEY_SOURCE_PORT_OPERATOR)==0) {
            if (!acl_parse_l4_operator
                (val,
                 OPS_CLS_L4_SRC_PORT_VALID,
                 &entry->entry_fields.entry_flags,
                 &entry->entry_fields.L4_src_port_op)) {
                VLOG_ERR("invalid L4 source port op %s", val);
                valid = false;
            }
        } else if (strcmp(name, ACE_KEY_SOURCE_PORT)==0) {
            if (!acl_parse_l4_port
                (val,
                 &entry->entry_fields.L4_src_port_min)) {
                VLOG_ERR("invalid L4 source port min %s", val);
                valid = false;
            }
        } else if (strcmp(name, ACE_KEY_SOURCE_PORT_MAX)==0) {
            if (!acl_parse_l4_port
                (val,
                 &entry->entry_fields.L4_src_port_max)) {
                VLOG_ERR("invalid L4 source port max %s", val);
                valid = false;
            }
        } else if (strcmp(name, ACE_KEY_DESTINATION_PORT_OPERATOR)==0) {
            if (!acl_parse_l4_operator
                (val,
                 OPS_CLS_L4_DEST_PORT_VALID,
                 &entry->entry_fields.entry_flags,
                 &entry->entry_fields.L4_dst_port_op)) {
                VLOG_ERR("invalid L4 destination port op %s", val);
                valid = false;
            }
        } else if (strcmp(name, ACE_KEY_DESTINATION_PORT)==0) {
            if (!acl_parse_l4_port
                (val,
                 &entry->entry_fields.L4_dst_port_min)) {
                VLOG_ERR("invalid L4 destination port min %s", val);
                valid = false;
            }
        } else if (strcmp(name, ACE_KEY_DESTINATION_PORT_MAX)==0) {
            if (!acl_parse_l4_port
                (val,
                 &entry->entry_fields.L4_dst_port_max)) {
                VLOG_ERR("invalid L4 destination port max %s", val);
                valid = false;
            }
        }
    }

    json_destroy(jsonace);
    return valid;
}
#endif

static bool
populate_entry_from_acl_entry(struct ops_cls_list_entry *entry,
                                const struct ovsrec_acl_entry *acl_entry)
{
    bool valid = true;

    /* TODO: support more than ipv4 */
    if (!acl_parse_ipv4_address
        (acl_entry->src_ip,
         OPS_CLS_SRC_IPADDR_VALID,
         &entry->entry_fields.entry_flags,
         &entry->entry_fields.src_ip_address.v4,
         &entry->entry_fields.src_ip_address_mask.v4,
         &entry->entry_fields.src_addr_family)) {
        VLOG_ERR("invalid source ip addr %s", acl_entry->src_ip);
        valid = false;
    }
    if (!acl_parse_ipv4_address
        (acl_entry->dst_ip,
         OPS_CLS_DEST_IPADDR_VALID,
         &entry->entry_fields.entry_flags,
         &entry->entry_fields.dst_ip_address.v4,
         &entry->entry_fields.dst_ip_address_mask.v4,
         &entry->entry_fields.dst_addr_family)) {
        VLOG_ERR("invalid destination ip addr %s", acl_entry->dst_ip);
        valid = false;
    }

    if (acl_entry->n_protocol == 0)
    {
        VLOG_INFO("populate_entry_from_acl_entry: Protocol not specified");
    }
    else
    {
    /* SB: @todo verify if business logic has validated protocol value */
    entry->entry_fields.protocol = acl_entry->protocol[0];
    entry->entry_fields.entry_flags |= OPS_CLS_PROTOCOL_VALID;
    }

    if (!acl_parse_actions(acl_entry->action,
                           &entry->entry_actions)) {
        VLOG_ERR("invalid action %s", acl_entry->action);
        valid = false;
    }

    if(acl_entry->n_src_l4_port_min
            && acl_entry->src_l4_port_min)
    {
        entry->entry_fields.L4_src_port_op = OPS_CLS_L4_PORT_OP_EQ;
        entry->entry_fields.entry_flags |= OPS_CLS_L4_SRC_PORT_VALID;
        entry->entry_fields.L4_src_port_min = acl_entry->src_l4_port_min[0];
    }

    if(acl_entry->n_src_l4_port_max
            && acl_entry->src_l4_port_max)
    {
        /* assumes port min was specified, so changes operator to range */
        entry->entry_fields.L4_src_port_op = OPS_CLS_L4_PORT_OP_RANGE;
        entry->entry_fields.entry_flags |= OPS_CLS_L4_SRC_PORT_VALID;
        entry->entry_fields.L4_src_port_max = acl_entry->src_l4_port_max[0];
    }

    if(acl_entry->n_src_l4_port_range_reverse
            && acl_entry->src_l4_port_range_reverse)
    {
        /* it assumes that CLI has validated port min and max are the same */
        entry->entry_fields.L4_src_port_op = OPS_CLS_L4_PORT_OP_NEQ;
    }


    if(acl_entry->n_dst_l4_port_min
            && acl_entry->dst_l4_port_min)
    {
        entry->entry_fields.L4_src_port_op = OPS_CLS_L4_PORT_OP_EQ;
        entry->entry_fields.entry_flags |= OPS_CLS_L4_DEST_PORT_VALID;
        entry->entry_fields.L4_dst_port_min = acl_entry->dst_l4_port_min[0];
    }

    if(acl_entry->n_dst_l4_port_max
            && acl_entry->dst_l4_port_max)
    {
        /* assumes port min was specified, so changes operator to range */
        entry->entry_fields.L4_src_port_op = OPS_CLS_L4_PORT_OP_RANGE;
        entry->entry_fields.entry_flags |= OPS_CLS_L4_DEST_PORT_VALID;
        entry->entry_fields.L4_dst_port_max = acl_entry->dst_l4_port_max[0];
    }

    if(acl_entry->n_dst_l4_port_range_reverse
            && acl_entry->dst_l4_port_range_reverse)
    {
        /* it assumes that CLI has validated port min and max are the same */
        entry->entry_fields.L4_dst_port_op = OPS_CLS_L4_PORT_OP_NEQ;
    }


    return valid;
}

static struct ops_cls_list*
ops_cls_list_new_from_acl(struct acl *acl)
{
    const struct ovsrec_acl *acl_row = acl->ovsdb_row;
    bool valid = true;

    struct ops_cls_list *list = ops_cls_list_new();
    list->list_id = acl->uuid;
    list->list_name = xstrdup(acl->name);
    list->list_type = acl->type;

    /* make a sorted copy of the ace strings from OVSDB */
    size_t n_aces = acl_row->n_cfg_aces;
    size_t n_sorted_aces = 0;
    struct db_ace *sorted_aces = NULL;
    if (n_aces > 0) {
        sorted_aces = xmalloc(n_aces * sizeof sorted_aces[0]);

        while (n_sorted_aces < n_aces) {
            /* TODO: Deal with comment ACE's
             *
             if (node->value.is_comment) {
                continue;
             }
            */
            sorted_aces[n_sorted_aces].sequence_number = acl_row->key_cfg_aces[n_sorted_aces];
            sorted_aces[n_sorted_aces].acl_entry = acl_row->value_cfg_aces[n_sorted_aces];
            ++n_sorted_aces;
        }
        if (n_sorted_aces > 0) {
            sort(n_sorted_aces, &sort_compare_aces, &sort_swap_aces,
                 sorted_aces);
        }
    }

    /* allocate our PI entries and convert from json */
    list->num_entries = n_sorted_aces + 1; /* +1 for implicit deny all */
    list->entries = xzalloc(list->num_entries * sizeof *list->entries);
    for (int i = 0; i < n_sorted_aces; ++i) {
        const struct db_ace *dbace = &sorted_aces[i];
        struct ops_cls_list_entry *entry = &list->entries[i];

        if (!populate_entry_from_acl_entry(entry, dbace->acl_entry)) {
            /* VLOG_ERR already emitted */
            valid = false;
        }
    }

    /* add implicit deny all to end */
    list->entries[n_sorted_aces].entry_actions.action_flags =
        OPS_CLS_ACTION_DENY;

    if (!valid) {
        ops_cls_list_delete(list);
        list = NULL;
    }

    free(sorted_aces);
    return list;
}

/*************************************************************
 * acl lookup routines
 *************************************************************/
static struct hmap all_acls_by_uuid = HMAP_INITIALIZER(&all_acls_by_uuid);
struct acl *
acl_lookup_by_uuid(const struct uuid* uuid)
{
    struct acl *acl;

    HMAP_FOR_EACH_WITH_HASH(acl, all_node_uuid, uuid_hash(uuid),
                            &all_acls_by_uuid) {
        if (uuid_equals(&acl->uuid, uuid)) {
            return acl;
        }
    }
    return NULL;
}


static enum ops_cls_type
acl_type_from_string(const char *str)
{
    if (strcmp(str, "ipv4")==0) {
        return OPS_CLS_ACL_V4;
    } else if (strcmp(str, "ipv6")==0) {
        return OPS_CLS_ACL_V6;
    } else {
        return OPS_CLS_ACL_INVALID;
    }
}

/************************************************************
 * acl_new() and acl_delete() are low-level routines that deal with PI
 * acl data structures. They take care off all the memorary
 * management, hmap memberships, etc. They DO NOT make any PD calls.
 ************************************************************/
static struct acl*
acl_new(const struct ovsrec_acl *ovsdb_row, unsigned int seqno)
{
    struct acl *acl = xzalloc(sizeof *acl);
    acl->uuid = ovsdb_row->header_.uuid;
    acl->name = xstrdup(ovsdb_row->name); /* we can outlive ovsdb row */
    acl->type = acl_type_from_string(ovsdb_row->list_type);

    acl->ovsdb_row = ovsdb_row;
    acl->delete_seqno = seqno;

    list_init(&acl->p2acls);
    /* acl->want_pi already NULL from xzalloc */

    /* link myself into all the lists/maps I'm supposed to be in */
    hmap_insert(&all_acls_by_uuid, &acl->all_node_uuid, uuid_hash(&acl->uuid));

    return acl;
}

static void
acl_delete(struct acl* acl)
{
    /* Only during a polite shutdown (which doesn't exist yet)
     * should we be doing low-level teardown on PI records that
     * are still interconnected.
     *
     * And even in that case, we'll need to make sure we teardown
     * acl_ports (and their contained p2acl records) before we
     * teardown the ACL records.
     */
    ovs_assert(list_is_empty(&acl->p2acls));

    hmap_remove(&all_acls_by_uuid, &acl->all_node_uuid);

    /* free up my cached copy of the PI API struct */
    ops_cls_list_delete(acl->want_pi); /* temporary until Change system in place */

    free(CONST_CAST(char *, acl->name));
    free(acl);
}

static void
acl_set_cfg_status(const struct ovsrec_acl *row, char *state, unsigned int code,
                   char *details)
{
    struct smap cfg_status;
    char code_str[10];
    //char version[25];

    smap_clone(&cfg_status, &row->status);

    /* Remove any values that exist */
    smap_remove(&cfg_status, ACL_CFG_STATUS_STR);
    smap_remove(&cfg_status, ACL_CFG_STATUS_VERSION);
    smap_remove(&cfg_status, ACL_CFG_STATUS_STATE);
    smap_remove(&cfg_status, ACL_CFG_STATUS_CODE);
    smap_remove(&cfg_status, ACL_CFG_STATUS_MSG);

    /* Add values to the smap */
    smap_add(&cfg_status, ACL_CFG_STATUS_STR, state);
    /*
     * TODO: Uncomment this code when UI fills the version field
     *
     * sprintf(version, "%" PRId64"", row->cfg_version);
     * smap_add(&cfg_status, ACL_CFG_STATUS_VERSION,
     *          version);
     */
    smap_add(&cfg_status, ACL_CFG_STATUS_STATE, state);
    sprintf(code_str, "%u", code);
    smap_add(&cfg_status, ACL_CFG_STATUS_CODE, code_str);
    smap_add(&cfg_status, ACL_CFG_STATUS_MSG, details);

    /* Write cfg_status column */
    ovsrec_acl_set_status(row, &cfg_status);

    /* TODO: Make this code work/
    ovsrec_acl_update_cfg_status_setkey(row, ACL_CFG_STATUS_STR, state);
    sprintf(version, "%" PRId64"", row->cfg_version);
    ovsrec_acl_update_cfg_status_setkey(row, ACL_CFG_STATUS_VERSION, version);
    ovsrec_acl_update_cfg_status_setkey(row, ACL_CFG_STATUS_STATE, state);
    sprintf(code_str, "%u", code);
    ovsrec_acl_update_cfg_status_setkey(row, ACL_CFG_STATUS_CODE, code_str);
    ovsrec_acl_update_cfg_status_setkey(row, ACL_CFG_STATUS_MSG, details); */
}

static void
acl_update_internal(struct acl* acl)
{
    /* Always translate/validate user input, so we can fail early
     * on unsupported values */

    char details[256];
    struct ops_cls_list *list = ops_cls_list_new_from_acl(acl);
    if (!list) {
        sprintf(details, "ACL %s -- unable to translate from ovsdb",
                acl->name);
        VLOG_DBG(details);
        acl_set_cfg_status(acl->ovsdb_row, ACL_CFG_STATE_REJECTED, 4, details);
        return;
    } else {
        /* delete old PI cache of API obj, and remember new one */
        ops_cls_list_delete(acl->want_pi); /* Temporary until Change system in place */
        acl->want_pi = list;
    }

    if (!list_is_empty(&acl->p2acls)) {
        /* Make the call down to the PD layer so it can change the
         * application of this ACL on all related ports.
         */
        struct ops_cls_pd_list_status status;
        memset(&status, 0, sizeof status);
        int rc = call_ofproto_ops_cls_list_update(acl, &status);

        if (rc == 0) {
            sprintf(details, "ACL %s -- PD list_update succeeded", acl->name);
            VLOG_DBG(details);
            ovsrec_acl_set_cur_aces(acl->ovsdb_row,
                                    acl->ovsdb_row->key_cfg_aces,
                                    acl->ovsdb_row->value_cfg_aces,
                                    acl->ovsdb_row->n_cfg_aces);
            acl_set_cfg_status(acl->ovsdb_row, ACL_CFG_STATE_APPLIED,
                               0, details);
        } else {
            sprintf(details, "ACL %s -- PD list_update failed for"
                    " acl entry = %u and port = %u", acl->name,
                     status.entry_id, status.port->ofp_port);
            VLOG_DBG(details);
            acl_set_cfg_status(acl->ovsdb_row, ACL_CFG_STATE_REJECTED,
                               status.status_code, details);
        }
    } else {
        sprintf(details, "ACL %s -- Not applied. No PD call necessary",
                acl->name);
        VLOG_DBG(details);
        ovsrec_acl_set_cur_aces(acl->ovsdb_row, acl->ovsdb_row->key_cfg_aces,
            acl->ovsdb_row->value_cfg_aces, acl->ovsdb_row->n_cfg_aces);
        acl_set_cfg_status(acl->ovsdb_row, ACL_CFG_STATE_APPLIED, 0, details);
    }
}

/************************************************************
 * acl_cfg_create(), acl_cfg_update(), acl_delete() are
 * the PI acl CRUD routines.
 ************************************************************/
static struct acl*
acl_cfg_create(const struct ovsrec_acl *ovsdb_row, unsigned int seqno)
{
    VLOG_DBG("ACL %s created", ovsdb_row->name);

    struct acl *acl = acl_new(ovsdb_row, seqno);

    /* TODO: Remove temporary processing of ACL:C like an ACL:U */
    acl_update_internal(acl);

    return acl;
}

static void
acl_cfg_update(struct acl* acl)
{
    VLOG_DBG("ACL %s changed", acl->name);
    acl_update_internal(acl);
}

static void
acl_cfg_delete(struct acl* acl)
{
    VLOG_DBG("ACL %s deleted", acl->name);

    /* Unapply ACL on any ports is handled as part of
       plugin reconfigure blocks.
       TODO: Check if there are any ports left and report error if the p2acl list is not empty*/

    acl_delete(acl);
}

/************************************************************
 * Top level routine to check if ACLs need to reconfigure
 ************************************************************/
void
acl_reconfigure_init(struct blk_params *blk_params)
{
    /* Quick check for ACL table changes */
    bool acls_created;
    bool acls_updated;
    bool acls_deleted;
    struct ovsdb_idl *idl;
    unsigned int idl_seqno;
    bool have_acls = !hmap_is_empty(&all_acls_by_uuid);

    VLOG_INFO("[%s] - acl_reconfigure_init called", ACL_PLUGIN_NAME);

    /* Get idl and idl_seqno to work with */
    idl = blk_params->idl;
    idl_seqno = blk_params->idl_seqno;

    const struct ovsrec_acl *acl_row = ovsrec_acl_first(idl);
    if (acl_row) {
        acls_created = OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(acl_row, idl_seqno);
        acls_updated = OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(acl_row, idl_seqno);

        /* We only care about acls_deleted if we already have some acls.
         * If this reconfigure is the result of an ovsdb reconnect, we have to
         * assume that records have been deleted while we were away. */
        acls_deleted = have_acls &&
            (blk_params->ovsdb_reconnected ||
             OVSREC_IDL_ANY_TABLE_ROWS_DELETED(acl_row, idl_seqno));
    } else {
        /* There are no ACL rows in OVSDB. */
        acls_created = false;
        acls_updated = false;
        acls_deleted = have_acls;
    }

    /* Check if we need to process any ACL:[CU]
     *   - ACL:C will show up as acls_created
     *   - ACL:U might not exist outside ACE:[CD]. Can an ACL's name or type
     *     be changed?
     * We also have to traverse if acls_deleted in order to mark/sweep.
     */
    if (acls_created || acls_updated || acls_deleted) {
        const struct ovsrec_acl *acl_row_next;
        OVSREC_ACL_FOR_EACH_SAFE(acl_row, acl_row_next, idl) {
            struct acl *acl = acl_lookup_by_uuid(&acl_row->header_.uuid);
            if (!acl) {
                acl = acl_cfg_create(acl_row, idl_seqno);
            } else {
                /* Always update these, even if nothing else has changed,
                 * The ovsdb_row may have changed out from under us.
                 * delete_seqno is use as mark/sweep to delete unused ACLs.
                 */
                acl->ovsdb_row = acl_row;
                acl->delete_seqno = idl_seqno;

                /* Check if this is an ACL:[CU] */
                bool row_changed =
                    (OVSREC_IDL_IS_ROW_MODIFIED(acl_row, idl_seqno) ||
                     OVSREC_IDL_IS_ROW_INSERTED(acl_row, idl_seqno));

                if (row_changed) {
                    acl_cfg_update(acl);
                }
            }
        }
    } else {
        VLOG_DBG("No changes in ACL table");
    }

    /* Detect any ACL:D by sweeping looking for old delete_seqno. */
    if (acls_deleted) {
        struct acl *acl, *next_acl;
        HMAP_FOR_EACH_SAFE (acl, next_acl, all_node_uuid, &all_acls_by_uuid) {
            if (acl->delete_seqno < idl_seqno) {
                /* TODO: After we use Change objects, move the
                 *       ACL:D handling to before ACL:[CU] */
                acl_cfg_delete(acl);
            }
        }
    }
}
