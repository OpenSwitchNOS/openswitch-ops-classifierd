/** @file qos_plugin.c
 */

/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <config.h>
#include "qos_plugin.h"
#include "qos_utils.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "plugin-extensions.h"
#include "reconfigure-blocks.h"
#include "shash.h"
#include "vswitch-idl.h"
#include "ofproto/ofproto-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(qos_plugin);

static bool plugin_init_done = false;

//************ Define plugin functions into a reconfigure block ***************//
//
// If a function of the plugin is considered as part of a global reconfigure
// event, it is necesary to register the function into a specific reconfigure
// block by calliing register_callback_block API:
//
// int register_reconfigure_callback(void (*callback_handler)(struct blk_params*)
//                                   enum block_id blk_id,
//                                   unsigned int priority);
//
// where:
//  - callback_handler: is the function pointer of the plugin.
//  - blk_id: identifies the block which the function will be registered.
//  - priority: affects the plugin initialization ordering.
//
//*****************************************************************************//

int init(int phase_id)
{
    int ret = 0;

    VLOG_INFO("[%s] Registering in BLK_INIT_RECONFIGURE", QOS_PLUGIN_NAME);
    register_reconfigure_callback(&qos_callback_init, BLK_INIT_RECONFIGURE, NO_PRIORITY);

    VLOG_INFO("[%s] Registering in BLK_BR_FEATURE_RECONFIG", QOS_PLUGIN_NAME);
    register_reconfigure_callback(&qos_callback_reconfigure,
                                  BLK_BR_FEATURE_RECONFIG, NO_PRIORITY);

    VLOG_INFO("[%s] Registering in BLK_RECONFIGURE_NEIGHBORS", QOS_PLUGIN_NAME);
    register_reconfigure_callback(&qos_callback_reconfigure,
                                  BLK_RECONFIGURE_NEIGHBORS, NO_PRIORITY);

    return ret;
}

int run(void)
{
    VLOG_DBG("[%s] is running...", QOS_PLUGIN_NAME);

    if (! plugin_init_done) {
        /**
         * Initialize the QOS API -- it will find its ASIC provider APIs.
         *
         * Must run after ASIC provider plugin initializes, therefore must
         * be called in the "run loop", as there is no "after all plugins
         * are initialized" callback.
         */
        qos_ofproto_init();
        plugin_init_done = true;
    }

    return 0;
}

int wait(void)
{
    VLOG_DBG("[%s] is waiting for...", QOS_PLUGIN_NAME);
    return 0;
}

int destroy(void)
{
    unregister_plugin_extension(QOS_PLUGIN_NAME);
    VLOG_DBG("[%s] was destroyed...", QOS_PLUGIN_NAME);
    return 0;
}
