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

#include "openswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovsdb-idl.h"
#include "qos_map.h"
#include "qos_profile.h"
#include "qos_utils.h"
#include "smap.h"
#include "vswitch-idl.h"


/* Configure QOS maps & profiles for a particular bridge. */
void qos_configure(struct ofproto *ofproto)
{
    qos_configure_cos_map(ofproto);

    qos_configure_dscp_map(ofproto);

    qos_configure_profiles(ofproto, NULL, NULL);
}
