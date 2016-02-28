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
#include "qos_map.h"
#include "qos_profile.h"
#include "qos_trust.h"
#include "qos_utils.h"

#include "openswitch-idl.h"
#include "ovsdb-idl.h"
#include "reconfigure-blocks.h"
#include "smap.h"
#include "vswitch-idl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(qos_utils);


// TODO: from bridge.h -- should come from bridge.h
struct port {
    struct hmap_node hmap_node; /* Element in struct bridge's "ports" hmap. */
    struct bridge *bridge;
    char *name;

    const struct ovsrec_port *cfg;

    /* An ordinary bridge port has 1 interface.
     * A bridge port for bonding has at least 2 interfaces. */
    struct ovs_list ifaces;    /* List of "struct iface"s. */
    int bond_hw_handle;        /* Hardware bond identifier. */
};

/**
 * Do whatever initialization needed by QOS feature at the ofproto layer.
 */
void
qos_ofproto_init(void)
{
    qos_ofproto_map_init();
    qos_ofproto_profile_init();
    qos_ofproto_trust_init();
}

/**
 * Configure QOS maps & profiles for a particular bridge.
 */
void qos_configure(struct ofproto *ofproto,
                   struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    qos_configure_cos_map(ofproto, idl, idl_seqno);

    qos_configure_dscp_map(ofproto, idl, idl_seqno);

    qos_configure_global_profiles(ofproto, idl, idl_seqno);
}

/**
 * bridge_reconfigure BLK_INIT_RECONFIGURE callback handler
 */
void qos_callback_init(struct blk_params *blk_params)
{

    /* check for global qos-trust change. */
    qos_configure_trust(blk_params->idl, blk_params->idl_seqno);

    /* do the global profiles */
    qos_configure(blk_params->ofproto, blk_params->idl, blk_params->idl_seqno);

    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d opfproto@ %p",
             __FUNCTION__,
             blk_params, blk_params->idl, blk_params->idl_seqno, blk_params->ofproto);
}

/**
 * bridge_reconfigure BLK_BR_xxx and BLK_VRF_xxx callback handler
 *
 * handles all Bridge- and VRF-type callbacks from bridge_reconfigure.
 */
void qos_callback_reconfigure(struct blk_params *blk_params)
{
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d opfproto@ %p ports@ %p",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->ports);

    /* loop through all ports */
    struct port *port;
    HMAP_FOR_EACH (port, hmap_node, blk_params->ports) {
        VLOG_DBG("%s: port %s", __FUNCTION__, port->cfg->name);

        qos_trust_send_change(blk_params->ofproto,
                              port, port->cfg,
                              blk_params->idl_seqno);

        qos_configure_port_profiles(blk_params->ofproto,
                                    port->cfg,
                                    port,
                                    blk_params->idl, blk_params->idl_seqno);
    }
}
