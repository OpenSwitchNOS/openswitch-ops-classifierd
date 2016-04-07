/*
 * Copyright (c) 2016 Hewlett-Packard Enterprise Development, LP
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


#include <stdlib.h>
#include <errno.h>
#include "list.h"
#include "openvswitch/vlog.h"
#include "vswitch-idl.h"
#include "stats-blocks.h"
#include "plugin-extensions.h"
#include "copp-asic-provider.h"
#include "vswitch-idl.h"
#include "system-stats.h"
#include "copp-temp-keys.h"


VLOG_DEFINE_THIS_MODULE(stats_copp_plugin);

/* Globals */
struct plugin_extension_interface g_copp_asic_plugin;
bool g_copp_initialized;

void copp_stats_cb(struct stats_blk_params *sblk, enum stats_block_id blk_id);

const char *const temp_copp_keys[COPP_NUM_CLASSES] = {
    [COPP_ACL_LOGGING] =        "temp_copp_acl_logging",
    [COPP_ARP_BROADCAST] =      "temp_copp_arp_broadcast",
    [COPP_ARP_MY_UNICAST] =     "temp_copp_arp_my_unicast",
    [COPP_ARP_SNOOP] =          "temp_copp_arp_snoop",
    [COPP_BGP] =               "temp_copp_bgp",
    [COPP_DEFAULT_UNKNOWN] =    "temp_copp_default_unknown",
    [COPP_DHCPv4] =             "temp_copp_dhcpv4",
    [COPP_DHCPv6] =             "temp_copp_dhcpv6",
    [COPP_ICMPv4_MULTIDEST] =   "temp_copp_icmpv4_multidest",
    [COPP_ICMPv4_UNICAST] =     "temp_copp_icmpv4_unicast",
    [COPP_ICMPv6_MULTICAST] =   "temp_copp_icmpv6_multicast",
    [COPP_ICMPv6_UNICAST] =     "temp_copp_icmpv6_unicast",
    [COPP_LACP] =               "temp_copp_lacp",
    [COPP_LLDP] =               "temp_copp_lldp",
    [COPP_OSPFv2_MULTICAST] =   "temp_copp_ospfv2_multicast",
    [COPP_OSPFv2_UNICAST] =     "temp_copp_ospfv2_unicast",
    [COPP_sFLOW_SAMPLES] =      "temp_copp_sflow_samples",
    [COPP_STP_BPDU] =           "temp_copp_stp_bpdu",
    [COPP_UNKNOWN_IP_UNICAST] = "temp_copp_unknown_ip_unicast"
};



/* IMPLEMENTATION NOTE:
 * init()
 * Trust the magic... this function really is called. Here's how it works:
 * ops-switchd:main calls plugins_init(path) just prior to bridge_init()
 * plugins_init() takes a path as an arg and calls plugins_initializaton(path)
 * plugins_initializaton(path) searches for any library files in path, dynamically
 * loads them and invokes each of their init() functions.
 *
 * The end effect is that a plugin can get loaded by ensuring two things
 *  1. it provides an init() fuction
 *  2. the make system installs it's library into the same path that plugins_init searches
 *
 * At the time of this writting, that special path was intended to be
 *    /usr/lib/openvswitch/plugins
 */
void init(void) {
    int rc;
    struct plugin_extension_interface* asic_intf;

    /* find the previously registered asic copp plugin */
    g_copp_initialized = false;
    rc = find_plugin_extension(COPP_ASIC_PLUGIN_INTERFACE_NAME,
        COPP_ASIC_PLUGIN_INTERFACE_MAJOR,
        COPP_ASIC_PLUGIN_INTERFACE_MINOR,
        &asic_intf);

    if (!rc) {
        g_copp_asic_plugin.plugin_interface = asic_intf->plugin_interface;
        g_copp_initialized = true;
    }
    else {
        /* log something */
    }

    /* FIXME: also register for STATS_PER_PORT and STATS_PER_IFACE and STATS_PER_VRF */
    register_stats_callback(copp_stats_cb, STATS_PER_BRIDGE, 0);

    VLOG_INFO("copp stats callback copp_stats_cb() registered");

}

void run() {
}
void wait() {
}
void destroy() {
}


void copp_stats_cb(struct stats_blk_params *sblk, enum stats_block_id blk_id) {

    int class, rc, len=0;
    struct copp_asic_plugin_interface* asic_intf = (struct copp_asic_plugin_interface*)g_copp_asic_plugin.plugin_interface;
    struct copp_protocol_stats  copp_stats;
    struct copp_hw_status  hw_status;
#define NUM_STATS_PER_CLASS 7
#define NUM_CHARS_UINT_64 21
#define NUM_COMMAS_AND_SUCH 8
#define STATS_BUF_SIZE ((NUM_STATS_PER_CLASS*NUM_CHARS_UINT_64) + NUM_COMMAS_AND_SUCH)
    char stats_buf[STATS_BUF_SIZE];
    const struct ovsrec_open_vswitch *cfg;

    struct smap *copp_smap;

    if (sblk->idl)
       cfg = ovsrec_open_vswitch_first(sblk->idl);
    else {
        /* error case. log somethign */
        return;
    }

    /* FIXME? we don't absolutly need this sanity check. Could do without it.
     * I originally implemented this based on a misunderstanding...it's not as needful as I thought.
     *
     * the cost of having this here is that we must implement ovsdb_idl_txn_is_inprogress()
     * in ovsdb.idl.c and suffer a review cycle in ops-openvswithch with the vain hope to
     * push upstream.
     */
    if (ovsdb_idl_txn_is_inprogress(sblk->idl) == false) {
        /* we are called from stats updation which should have a live idl->txn in place already */
        VLOG_DBG("%s missing txn", __FUNCTION__);
        return;
    }

    //BUG? xmalloc() is heavily used else where, but that seems bad to me.
    copp_smap = malloc(sizeof *copp_smap);
    if (!copp_smap) {
        VLOG_ERR("could not sample copp stats. out of memory");
        return;
    }
    smap_init(copp_smap);

    for (class=0; class<COPP_NUM_CLASSES; class++) {
        /* collect from asic */
        /* FIXME, use correct hw_asic_id */
        /* FIXME, check rc(s) */
        rc = asic_intf->copp_stats_get(0, class, &copp_stats);
        rc = asic_intf->copp_hw_status_get(0, class, &hw_status);

        len = snprintf(stats_buf, STATS_BUF_SIZE,
            TEMP_COPP_STATS_BUF_FMT,
            TEMP_COPP_STATS_VARS(hw_status, copp_stats) );
        if (len < 0) {
            /* error case */
            /* FIXME log and clean up */
            return;
        }
        if (len > STATS_BUF_SIZE) {
            /* error case */
            /* FIXME log and clean up */
            return;
        }
        VLOG_INFO("asic_intf->copp_stats_get returned %d with stats %s:%s", rc, temp_copp_keys[class], stats_buf);

        /* publish to db */
        smap_add(copp_smap, temp_copp_keys[class], stats_buf);

    }


    if (cfg) {
        /* FIXME? this depends upon code added to bridge_init:
         * ovsdb_idl_omit_alert(idl, &ovsrec_system_col_copp_statistics);
         * will suffer a review cycle on ops-switch (not terrible) if we don't
         * find a way to efficiently omit_alert here in the plugin.
         */
        ovsrec_system_set_copp_statistics(cfg, copp_smap);
    }

    free(copp_smap);

}
