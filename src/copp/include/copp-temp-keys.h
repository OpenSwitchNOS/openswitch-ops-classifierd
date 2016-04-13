/*
 * Copyright (c) 2016 Hewlett Packard Enterprise Development LP
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
 *
 *
 * Control Plane Policing (COPP) SwitchD ASIC Provider API
 *
 * Declares the functions and data structures that are used between the
 * SwitchD COPP feature and ASIC-specific providers.
 */


#ifndef COPP_TEMP_KEYS_H
#define COPP_TEMP_KEYS_H 1

#ifdef  __cplusplus
extern "C" {
#endif

#include "copp-asic-provider.h"

/*
 * Use designated initializer to pre-fill an array of pointer to key names
 * for each enum use by the API.
 */



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

#define TEMP_COPP_STATS_BUF_FMT "%lu,%lu,%lu,%lu,%lu,%lu,%lu "
#define TEMP_COPP_STATS_VARS(h, c)         \
        h.rate, h.burst, h.local_priority,  \
        c.packets_passed, c.bytes_passed,   \
        c.packets_dropped, c.bytes_dropped

#endif /* COPP_TEMP_KEYS_H */
