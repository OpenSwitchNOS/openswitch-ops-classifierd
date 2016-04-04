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

#include "p2acl.h"
#include "acl_port.h"
#include "vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "reconfigure-blocks.h"
#include "acl_plugin.h"

VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin_port);

/*************************************************************
 * acl_port search routines
 *************************************************************/
static struct hmap all_ports = HMAP_INITIALIZER(&all_ports);
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

/************************************************************
 * acl_port_new() and acl_port_delete() are low-level routines that
 * deal with PI acl_port data structures. They take care off all the
 * memorary management, hmap memberships, etc. They DO NOT make any PD
 * calls.
 ************************************************************/
static struct acl_port*
acl_port_new(const struct ovsrec_port *ovsdb_row, unsigned int seqno)
{
    struct acl_port *port = xzalloc(sizeof *port);
    port->uuid = ovsdb_row->header_.uuid;
    port->name = xstrdup(ovsdb_row->name); /* we can outlive ovsdb_row */

    /* setup my p2acls to know about me and which colgrp they represent */
    for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
        p2acl_construct(&port->p2acls[i], port, i);
    }

    port->ovsdb_row = ovsdb_row;
    port->delete_seqno = seqno;
    hmap_insert(&all_ports, &port->all_node_uuid, uuid_hash(&port->uuid));
    return port;
}

static void
acl_port_delete(struct acl_port* port)
{
    if (port) {
        hmap_remove(&all_ports, &port->all_node_uuid);
        free(CONST_CAST(char *, port->name));

        /* cleanup my p2acls */
        for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
            p2acl_destruct(&port->p2acls[i]);
        }

        free(port);
    }
}

/************************************************************
 * acl_port_cfg_create(), acl_port_cfg_update(), acl_port_delete() are
 * the PI acl CRUD routines.
 ************************************************************/
static struct acl_port*
acl_port_cfg_create(struct port *port, unsigned int seqno,
                    struct ofproto *ofproto)
{
    VLOG_DBG("PORT %s created", port->cfg->name);
    struct acl_port *acl_port = acl_port_new(port->cfg, seqno);

    for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
        p2acl_cfg_create(&acl_port->p2acls[i], port, ofproto);
    }

    return acl_port;
}

static void
acl_port_cfg_update(struct acl_port *acl_port, struct port *port,
                    struct ofproto *ofproto)
{
    VLOG_DBG("PORT %s changed", acl_port->name);
    /* TODO: rework this when we have the full
       Change/Transaction structure */
    /* Defer PD update to P2ACL structs */
    for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
        p2acl_cfg_update(&acl_port->p2acls[i], port, ofproto);
    }
}

static void
acl_port_cfg_delete(struct acl_port* acl_port, struct port *port,
                    struct ofproto *ofproto)
{
    VLOG_DBG("PORT %s deleted", port->name);
    for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
        p2acl_cfg_delete(&acl_port->p2acls[i], port, ofproto);
    }

    /* There's nothing to log to OVSDB for an PORT:D */
    acl_port_delete(acl_port);
}

/************************************************************
 * Top level routine to check if PORTs need to reconfigure
 ************************************************************/
void acl_callback_port_delete(struct blk_params *blk_params)
{
    /* Handle port deletes here */
    bool have_ports = !hmap_is_empty(&all_ports);
    struct port *port;
    struct acl_port *acl_port;

    if (!have_ports) {
        VLOG_DBG("[%s]No ports to delete", ACL_PLUGIN_NAME);
        return;
    }
    /* There are ports to delete. Run through the list of ports */
    HMAP_FOR_EACH(port, hmap_node, blk_params->ports) {
       acl_port = port_lookup(&port->cfg->header_.uuid);
       if (acl_port) {
           acl_port_cfg_delete(acl_port, port, blk_params->ofproto);
       }
    }
}

void acl_callback_port_reconfigure(struct blk_params *blk_params)
{
    struct acl_port *acl_port;
    struct port *port = NULL;

    /* Port modify routine */
    HMAP_FOR_EACH(port, hmap_node, blk_params->ports) {
        if ((OVSREC_IDL_IS_ROW_MODIFIED(port->cfg, blk_params->idl_seqno) ||
            (OVSREC_IDL_IS_ROW_INSERTED(port->cfg, blk_params->idl_seqno))) &&
            port->cfg->aclv4_in_cfg) {
            acl_port = port_lookup(&port->cfg->header_.uuid);
            if (!acl_port) {
                /* We ned to create a port here */
                acl_port_cfg_create(port, blk_params->idl_seqno,
                                    blk_params->ofproto);
            } else {
                acl_port->ovsdb_row = port->cfg;
                acl_port->delete_seqno = blk_params->idl_seqno;
                acl_port_cfg_update(acl_port, port, blk_params->ofproto);
            }
        }
    }
}
