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

/* use copp_totals to index this array */
uint64_t g_copp_stasts_totals[COPS_STSTS_TOTAL_MAX] = {0,0,0,0};

typedef struct copp_stats_errors_logged {
   bool no_supp     : 1;
   bool inval       : 1;
} copp_stats_errors_logged_t;

typedef struct copp_stauts_errors_logged {
   bool no_supp     : 1;
   bool no_spc      : 1;
   bool io          : 1;
   bool inval       : 1;
} copp_stauts_errors_logged_t;

copp_stats_errors_logged_t  g_copp_stats_log_info[COPP_NUM_CLASSES];

/* FIXME? don't need this? */
copp_stauts_errors_logged_t g_copp_status_log_info[COPP_NUM_CLASSES];


void copp_stats_cb(struct stats_blk_params *sblk, enum stats_block_id blk_id);



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
    int i, rc;
    struct plugin_extension_interface* asic_intf;

    /* find the previously registered asic copp plugin */
    g_copp_initialized = false;
    rc = find_plugin_extension(COPP_ASIC_PLUGIN_INTERFACE_NAME,
        COPP_ASIC_PLUGIN_INTERFACE_MAJOR,
        COPP_ASIC_PLUGIN_INTERFACE_MINOR,
        &asic_intf);
    if (rc) {
        VLOG_WARN("Could not find copp stats asic plugin. Will not retister for switchd stats plugin");
        return;
    }

    /* register our callback on PER_BRIDGE. */
    rc = register_stats_callback(copp_stats_cb, STATS_PER_BRIDGE, 0);
    if (rc) {
        VLOG_WARN("Failed to retister for switchd stats plugin");
        g_copp_asic_plugin.plugin_interface = NULL;
        g_copp_initialized = false;
        return;
    }

    /* initialize global vars */
    for (i=0; i < COPS_STSTS_TOTAL_MAX; i++) {
        g_copp_stasts_totals[i] =0;
    }
    for (i=0; i < COPP_NUM_CLASSES; i++) {
        g_copp_stats_log_info[i].no_supp = false;
        g_copp_stats_log_info[i].inval= false;

        g_copp_status_log_info[i].no_supp = false;
        g_copp_status_log_info[i].no_spc= false;
        g_copp_status_log_info[i].io = false;
        g_copp_status_log_info[i].inval= false;
    }
    g_copp_asic_plugin.plugin_interface = asic_intf->plugin_interface;
    g_copp_initialized = true;

    VLOG_INFO("callback copp_stats_cb() registered");

}


/* The copp stats system has no need of employing run, wait, or destroy
 * functions. However, the plugin system dynamic lyncing demands that
 * these functions be present in our library or the plugin will not load.
 */
void run() {
}
void wait() {
}
void destroy() {
}


/* copp_stats_cb
 * This gathers COPP stats from a PD layer and publishes them to the ovsdb via
 * the IDL.
 * We loop through every class in copp_protocol_class and ask the PD layer for
 * its view of each one of them. We build up an smap of all the answers. Then
 * we tack on some totals rows into the smap. Then publish it.
 *
 * If a PD layer returns an error for any call, we publish -1s into the DB for
 * that row and send a WARN log (only on the first call).
 *
 * It's aslo fair for an PD layer to tell us -1, which we will faithfully
 * publish to the DB without logging anything.
 *
 * Each time we querry a PD layer for stats, we are seeking four stats. If the
 * PD layer partially supports them, it should send us real values for those it
 * supports, -1s for those it does not, and return a non-error status (0).
 *
 * Each time we querry a PD layer for status, we are seeking three stats. PD
 * layer must support all three of these or return an error status.
 */
/* IMPLEMENTATION NOTE:
 * At the time an execute_stats_block() is called from swithcd, there is
 * already an idl transaction in flight. We assume that transaction is live/
 * valid and tack on our column rows to it. We also assume that switchd will
 * soon commit that transaction.
 */
void
copp_stats_cb(struct stats_blk_params *sblk, enum stats_block_id blk_id) {

    int class, rc, len=0;
    const struct copp_asic_plugin_interface* asic_intf =
        (struct copp_asic_plugin_interface*)g_copp_asic_plugin.plugin_interface;
    struct copp_protocol_stats  copp_stats;
    struct copp_hw_status  hw_status;
    const struct ovsrec_open_vswitch *cfg;
    struct smap copp_smap;
#define NUM_STATS_PER_CLASS 7
#define NUM_CHARS_UINT_64 21
#define NUM_COMMAS_AND_SUCH 8
#define STATS_BUF_SIZE ((NUM_STATS_PER_CLASS*NUM_CHARS_UINT_64) + NUM_COMMAS_AND_SUCH)
    char stats_buf[STATS_BUF_SIZE];

    /* sanity checking */
    if (sblk->idl)
       cfg = ovsrec_open_vswitch_first(sblk->idl);
    else {
        /* error case. log somethign */
        return;
    }

    /* starting */
    smap_init(&copp_smap);

    for (class=0; class < COPP_NUM_CLASSES; class++) {
        /* collect from asic */
        /* FIXME, use correct hw_asic_id */
        rc = asic_intf->copp_stats_get(0, class, &copp_stats);
        if (rc) {
            copp_stats.bytes_passed =
            copp_stats.bytes_dropped =
            copp_stats.packets_passed =
            copp_stats.packets_dropped = -1;

            switch(rc) {
                case EOPNOTSUPP :
                    if (g_copp_stats_log_info[class].no_supp == false ) {
                        VLOG_WARN("copp_stats_get for class %d returned %d %s", class, rc, strerror(rc));
                        g_copp_stats_log_info[class].no_supp = true;
                    }
                    break;
                case EINVAL :
                    if (g_copp_stats_log_info[class].inval == false ) {
                        VLOG_WARN("copp_stats_get for class %d returned %d %s", class, rc, strerror(rc));
                        g_copp_stats_log_info[class].inval= true;
                    }
                    break;
                default:
                    VLOG_WARN("copp_stats_get for class %d returned unrecognized %d %s", class, rc, strerror(rc));
            }


        }

        if (!rc) {
            g_copp_stasts_totals[COPP_STATS_TOTAL_BYTES_DROPPED] += copp_stats.bytes_dropped;
            g_copp_stasts_totals[COPP_STATS_TOTAL_BYTES_PASSED] +=  copp_stats.bytes_passed;
            g_copp_stasts_totals[COPP_STATS_TOTAL_PKTS_DROPPED] += copp_stats.packets_dropped;
            g_copp_stasts_totals[COPS_STSTS_TOTAL_PKTS_PASSED] += copp_stats.packets_passed;
        }

        rc = asic_intf->copp_hw_status_get(0, class, &hw_status);
        if (rc) {
            hw_status.rate =
            hw_status.burst =
            hw_status.local_priority = -1;
            /* FIXME? is it appropriate to log these every time? */
            VLOG_INFO("copp_hw_status_get() for class %d returned %d %s", class, rc, strerror(rc));
        }

        len = snprintf(stats_buf, STATS_BUF_SIZE,
            TEMP_COPP_STATS_BUF_FMT,
            TEMP_COPP_STATS_VARS(hw_status, copp_stats));
        if (len < 0) {
            VLOG_WARN("could not convert stats to string. Not reporting class %d", class);
            goto out;
        }
        if (len > STATS_BUF_SIZE) {
            VLOG_WARN("stringifying stats would over buffer space (should not happen). Not reporting class %d", class);
            goto out;
        }

        /* Looks good.  Publish to db */
        smap_replace(&copp_smap, temp_copp_keys[class], stats_buf);

    }

    for (int tots=0; tots<COPS_STSTS_TOTAL_MAX; tots++) {

        len = snprintf(stats_buf, STATS_BUF_SIZE,
            "%lu", g_copp_stasts_totals[tots]);
        if (len < 0) {
            VLOG_WARN("could not convert totals to string. Not reporting total[%d]", tots);
            goto out;
        }
        if (len > STATS_BUF_SIZE) {
             VLOG_WARN("stringifying totals would over buffer space (should not happen). Not reporting total[%d]", tots);
            goto out;
        }

        /* publish to db */
        smap_replace(&copp_smap, temp_copp_totals_keys[tots], stats_buf);

    }


    if (cfg) {
        /* IMPLEMENTATION NOTE:
        * The call to ovsrec_system_set_copp_statistics() depends upon changes
        * in ops-switchd/src/bridge.c:bridge_init() to omit_alert on the copp
        * stats column.  (search ovsrec_system_col_copp_statistics)
        * We might be able to omit_alert here in this plugin's init() fucnciton
        * if the loader would pass either cfg or idl or stats_blk to us.
        */
        ovsrec_system_set_copp_statistics(cfg, &copp_smap);
    }
out:
    smap_destroy(&copp_smap);

}
