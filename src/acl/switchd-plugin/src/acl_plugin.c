/**************************************************************************//**
 * @file acl_plugin.c
 *
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
 *****************************************************************************/
#include "openvswitch/vlog.h"
#include "plugin-extensions.h"
#include "acl.h"
#include "acl_plugin.h"
#include "p2acl.h"
#include "acl_port.h"

VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin);

static bool plugin_init_done = false;

/*************************************************************************//**
 * ACL plugin for switchd. This file contains plugin functions that register
 * callbacks into reconfigure blocks.
 ****************************************************************************/
int init (int phase_id)
{
    /* Register callbacks */
    VLOG_INFO("ACL_PLUGIN - Registering in BLK_INIT_RECONFIGURE");
    register_reconfigure_callback(&acl_reconfigure_init, BLK_INIT_RECONFIGURE,
                                  NO_PRIORITY);
    VLOG_INFO("[%s] - Registering in BLK_BR_DELETE_PORTS", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_delete,
                                  BLK_BR_DELETE_PORTS, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering in BLK_VRF_DELETE_PORTS", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_delete,
                                  BLK_VRF_DELETE_PORTS, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering in BLK_BR_RECONFIGURE_PORTS",
              ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_reconfigure,
                                  BLK_BR_RECONFIGURE_PORTS, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering in BLK_VRF_RECONFIGURE_PORTS",
              ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_reconfigure,
                                  BLK_VRF_RECONFIGURE_PORTS, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering in BLK_BR_ADD_PORTS", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_reconfigure,
                                  BLK_BR_ADD_PORTS, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering in BLK_VRF_ADD_PORTS", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_reconfigure,
                                  BLK_VRF_ADD_PORTS, NO_PRIORITY);

    /* Initialize P2ACL column groups */
    p2acl_colgroup_init();

    return 0;
}

int run(void)
{
    if (!plugin_init_done) {
        acl_ofproto_init();
        plugin_init_done = true;
    }

    VLOG_DBG("ACL_PLUGIN is running");
    return 0;
}

int wait(void)
{
    VLOG_DBG("ACL_PLUGIN is waiting..");
    return 0;
}

int destroy(void)
{
    unregister_plugin_extension("ACL_PLUGIN");
    VLOG_DBG("ACL_PLUGIN was destroyed");
    return 0;
}