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

#ifndef __QOS_PLUGIN_H__
#define __QOS_PLUGIN_H__


#include "ofproto/ofproto-provider.h"
#include "reconfigure-blocks.h"

#define QOS_PLUGIN_NAME    "qos" //Do not change this name
#define QOS_PLUGIN_MAJOR    0
#define QOS_PLUGIN_MINOR    1


void qos_ofproto_init(void);


/**
 * Configure QOS maps & profiles for a bridge
 * @param params
 */
void qos_configure(struct ofproto *ofproto, struct ovsdb_idl *idl, unsigned int idl_seqno);

void qos_callback_init(struct blk_params *params);
void qos_callback_reconfigure(struct blk_params *params);

#endif //__QOS_PLUGIN_H__
