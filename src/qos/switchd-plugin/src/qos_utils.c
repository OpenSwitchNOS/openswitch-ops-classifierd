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

#include "qos_utils.h"

#include "qos_map.h"
#include "qos_profile.h"
#include "qos_trust.h"

#include "bridge.h"
#include "openswitch-idl.h"
#include "ovsdb-idl.h"
#include "reconfigure-blocks.h"
#include "smap.h"
#include "vswitch-idl.h"
#include "vrf.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(qos_utils);


/* First time, must set global QoS parameters before anything else happens. */
static bool firstTimeInitialization = true;


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
 *
 * called at the start of bridge_reconfigure, before anything has been
 * added, deleted or updated.
 *
 * First time only -- set global trust & profiles, so they exist prior
 * to any port being configured.
 */
void qos_callback_init_reconfigure(struct blk_params *blk_params)
{

    /* Check for global qos-trust change. */
    qos_configure_trust(blk_params->idl, blk_params->idl_seqno);

    if (firstTimeInitialization) {
        /* do the global profiles */
        qos_configure(blk_params->ofproto, blk_params->idl, blk_params->idl_seqno);

        VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p",
                 __FUNCTION__,
                 blk_params, blk_params->idl, blk_params->idl_seqno, blk_params->ofproto);

        firstTimeInitialization = false;
    }
}

/**
 * check all ports in a bridge or VRF, configuring trust and/or profiles
 * as needed.
 *
 * handles all Bridge- and VRF- reconfigure-type callbacks
 */
void qos_callback_reconfigure(struct blk_params *blk_params, struct hmap *ports)
{
    struct port     *port;

    /* loop through all ports */
    HMAP_FOR_EACH(port, hmap_node, ports) {
#ifdef DEBUG
        VLOG_DBG("%s: port %s", __FUNCTION__, port->cfg->name);
#endif

        qos_trust_send_change(blk_params->ofproto,
                              port, port->cfg,
                              blk_params->idl_seqno);

        qos_configure_port_profiles(blk_params->ofproto,
                                    port->cfg, port,
                                    blk_params->idl, blk_params->idl_seqno);
    }
}

/**
 * bridge_reconfigure BLK_BR_PORT_UPDATE callback
 *
 * called after port_configure on a single bridge port
 */
void
qos_callback_bridge_port_update(struct blk_params *blk_params)
{
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p br@ %p port@ %p (%s)",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->br,
             blk_params->port, blk_params->port->name);
    qos_trust_send_change(blk_params->ofproto,
                          blk_params->port, blk_params->port->cfg,
                          blk_params->idl_seqno);
}

/**
 * bridge_reconfigure BLK_VRF_PORT_UPDATE callback
 *
 * called after port_configure on a single VRF port
 */
void
qos_callback_vrf_port_update(struct blk_params *blk_params)
{
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p vrf@ %p port@ %p (%s)",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->vrf,
             blk_params->port, blk_params->port->name);
    qos_trust_send_change(blk_params->ofproto,
                          blk_params->port, blk_params->port->cfg,
                          blk_params->idl_seqno);
}

/**
 * bridge_reconfigure BLK_BR_FEATURE_RECONFIG callback
 *
 * called after everything for a bridge has been add/deleted/updated
 */
void
qos_callback_bridge_feature_reconfig(struct blk_params *blk_params)
{
    /* Look for global QoS changes only after all ports on the bridge
     * have been reconfigured.
     *
     * First time only, these checks were done in the init_reconfigure callback,
     * so skip them here.
     */
    if ( ! firstTimeInitialization) {
        /* do the global profiles */
        qos_configure(blk_params->ofproto, blk_params->idl, blk_params->idl_seqno);

#ifdef DEBUG
        VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p",
                 __FUNCTION__,
                 blk_params, blk_params->idl, blk_params->idl_seqno, blk_params->ofproto);
#endif

    }

#ifdef DEBUG
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p vrf@ %p ports@ %p",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->br, &blk_params->br->ports);
#endif

    qos_callback_reconfigure(blk_params, &blk_params->br->ports);
}

/**
 * bridge_reconfigure BLK_RECONFIGURE_NEIGHBORS callback
 *
 * called after everything for a VRF has been add/deleted/updated
 */
void
qos_callback_reconfigure_neighbors(struct blk_params *blk_params)
{

    /* Look for global QoS changes only after all ports on the bridge
     * have been reconfigured.
     *
     * First time only, global profile checks were done in the
     * init_reconfigure callback, so skip them here.
     */
    if ( ! firstTimeInitialization) {
        /* do the global profiles */
        qos_configure(blk_params->ofproto, blk_params->idl, blk_params->idl_seqno);

#ifdef DEBUG
        VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p",
                 __FUNCTION__,
                 blk_params, blk_params->idl, blk_params->idl_seqno, blk_params->ofproto);
#endif

    }

#ifdef DEBUG
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p vrf@ %p ports@ %p",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->vrf, &blk_params->vrf->up->ports);
#endif
    qos_callback_reconfigure(blk_params, &blk_params->vrf->up->ports);
}

/**
 * bridge_reconfigure BLK_BRIDGE_INIT callback handler
 */
void qos_callback_bridge_init(struct blk_params *blk_params)
{
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_port_col_qos_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_system_col_qos_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_system_col_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_interface_col_queue_tx_bytes);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_interface_col_queue_tx_packets);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_interface_col_queue_tx_errors);
}
