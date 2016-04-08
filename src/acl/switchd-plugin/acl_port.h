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

#ifndef __SWITCHD__PLUGIN__ACL_PORT_H__
#define __SWITCHD__PLUGIN__ACL_PORT_H__ 1

#include "hmap.h"
#include "uuid.h"
#include "reconfigure-blocks.h"
#include "acl_port_binding_helper.h"

/*************************************************************
 * acl_port structures
 *
 * Structures to store ACL-specific information about each port
 *
 * There should be one of these for every 'struct port'
 * maintained by bridge.c.
 *
 * TODO: Once switchd refactor is complete, we should use their
 * methods to track changes in bridge.c managed port structures.
 * For now we track the Port OVSDB table ourselves and then go
 * query bridge.c to get it's port structure right before making
 * PD calls.
 *************************************************************/
struct acl_port {
    struct hmap_node   all_node_uuid; /* In 'all_acl_ports'. */
    struct uuid        uuid;

    /* TEMPORARY: So we can find 'struct port' from bridge.c. */
    /* TODO: After switchd refactor, change this to be a
     *       'struct port *'
     *       Can't store it now, because we're not listening
     *       to bridge.c port CRUD events.
     */
    const char        *name;

    /* Hold all of my p2acl records internally, no need to
       allocate them separately. */
    struct p2acl p2acls[NUM_P2ACL_COLGRPS];

    const struct ovsrec_port *ovsdb_row;
    unsigned int       delete_seqno; /* mark/sweep to identify deleted */
};

/*************************************************************
 * acl_port search routines
 *************************************************************/
struct acl_port *acl_port_lookup_by_uuid(const struct uuid* uuid);

/************************************************************
 * Top level routine to check if a port's ACLs need to reconfigure
 ************************************************************/

/**************************************************************************//**
 * Reconfigure block callback for port delete operation.
 * This function is called when @see bridge_reconfigure() is called from
 * switchd. This callback will look for all ports that are about to be deleted
 * and unapply any applied ACLs from such ports
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 *****************************************************************************/
void acl_callback_port_delete(struct blk_params *blk_params);

/**************************************************************************//**
 * Reconfigure block callback for port reconfigure operation.
 * This function is called when @see bridge_reconfigure() is called from
 * switchd. This callback will look for all ports that are modified
 * and reconfigure ACL on such such ports
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 *****************************************************************************/
void acl_callback_port_reconfigure(struct blk_params *blk_params);

/**************************************************************************//**
 * Reconfigure block callback for Port Update operation.
 * This function is called when @see port_configure() is called from switchd.
 * At this point in time, switchd has finished configuring a port in PI and
 * PD data structures. During init sequence, if we encounter a port row
 * that has an ACL applied in the cfg column, that ACL will be applied to
 * the given port from here.
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 *****************************************************************************/
void acl_callback_port_update(struct blk_params *blk_params);

#endif  /* __SWITCHD__PLUGIN__ACL_PORT_H__ */