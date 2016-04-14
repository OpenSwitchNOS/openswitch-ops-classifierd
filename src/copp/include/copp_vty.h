/*
 * CoPP CLI Implementation
 *
 * (C) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 */

#include "copp-temp-keys.h"

#define COPP_STR        "Show COPP information\n"
#define STATISTICS_STR  "Show COPP Statistics information\n"
#define COPP_SHOW_CMD   "show copp statistics (bgp|ospfv2-unicast|ospfv2-multicast|" \
                        "lldp|lacp|arp-unicast|arp-broadcast|icmpv4-unicast|" \
                        "icmpv4-multidest|icmpv6-unicast|icmpv6-multicast|" \
                        "dhcpv4|dhcpv6|acl-logging|sflow|unknown-ip|unclassified)"

#define COPP_ZERO_STRING          "0"
#define COPP_DEFAULT_STATS_STRING "0,0,0,0,0,0,0"

#define COPP_STATS_PROTOCOL_MAX_LENGTH     12

#define COPP_VALIDATE_BUFFER(buf)          \
    if(buf == NULL) {                      \
        buf = COPP_DEFAULT_STATS_STRING;   \
    }

enum copp_protocol_class {
    COPP_ACL_LOGGING,
    COPP_ARP_BROADCAST,
    COPP_ARP_MY_UNICAST,    /* Unicast MAC or broadcast w/ TPA=switch IP */
    COPP_ARP_SNOOP,         /* Unicast ARPs not to any switch MAC */
    COPP_BGP,
    COPP_DEFAULT_UNKNOWN,   /* Packets not matching any other class */
    COPP_DHCPv4,
    COPP_DHCPv6,
    COPP_ICMPv4_MULTIDEST,  /* Broadcast or multicast */
    COPP_ICMPv4_UNICAST,
    COPP_ICMPv6_MULTICAST,
    COPP_ICMPv6_UNICAST,
    COPP_LACP,
    COPP_LLDP,
    COPP_OSPFv2_MULTICAST,  /* All OSPF Router address, etc */
    COPP_OSPFv2_UNICAST,
    COPP_sFLOW_SAMPLES,     /* Packets sent to CPU to be sFlow encapsated */
    COPP_STP_BPDU,
    COPP_UNKNOWN_IP_UNICAST
};
