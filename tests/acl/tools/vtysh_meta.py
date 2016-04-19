# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Vtysh meta-specification file.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from collections import OrderedDict


VTYSH_SPEC = OrderedDict([
    ('root', {
        'doc': '',
        'arguments': [],
        'pre_commands': [],
        'post_commands': [],
        'commands': [
            {
                'command': 'show interface {port}',
                'doc': 'Interface infomation.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    },
                ],
                'returns': True
            },
            {
                'command': 'show vlan {vlanid}',
                'doc': 'Show VLAN configuration.',
                'arguments': [
                    {
                        'name': 'vlanid',
                        'doc': 'Vlan ID number.',
                        'optional': True
                    }

                ],
                'returns': True
            },
            {
                'command': 'show lacp interface {port}',
                'doc': 'Show LACP interface.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    }
                ],
                'returns': True
            },
            {
                'command': 'show lacp aggregates {lag}',
                'doc': 'Show LACP aggregates.',
                'arguments': [
                    {
                        'name': 'lag',
                        'doc': 'Link-aggregate name.',
                        'optional': True
                    }
                ],
                'returns': True
            },
            {
                'command': 'show lacp configuration',
                'doc': 'Show LACP configuration.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show lldp neighbor-info {port}',
                'doc': 'Show global LLDP neighbor information.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.'
                    }
                ],
                'returns': True
            },
            {
                'command': 'show lldp statistics',
                'doc': 'Show LLDP statistics.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip bgp summary',
                'doc': 'Show bgp neighbors information summary.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip bgp neighbors',
                'doc': 'Show bgp neighbors information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip bgp',
                'doc': 'Show bgp routing information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ipv6 bgp',
                'doc': 'Show bgp routing information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show running-config',
                'doc': 'Show running-config information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip route',
                'doc': 'Show Routing Table.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ipv6 route',
                'doc': 'Display the routing table.',
                'arguments': [],
                'returns': True
            },
            # TODO: Add support for the show udld (shows all interfaces) cmd
            {
                'command': 'show udld interface {port}',
                'doc': 'Show UDLD information for the interface.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    },
                ],
                'returns': True
            },
            {
                'command': 'show rib',
                'doc': 'Show Routing Information Base.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip ecmp',
                'doc': 'Show ECMP Configuration',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'clear udld statistics',
                'doc': 'Clear UDLD statistics from all interfaces.',
                'arguments': [],
            },
            {
                'command': 'clear udld statistics interface {port}',
                'doc': 'Clear UDLD statistics for the interface.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    },
                ],
            },
            {
                'command': 'ping {destination} repetitions {count}',
                'doc': 'Send IPv4 ping',
                'arguments': [
                    {
                        'name': 'destination',
                        'doc': '<A.B.C.D> IPv4 address.'
                    },
                    {
                        'name': 'count',
                        'doc': 'Number of packets to send.'
                    }
                ],
                'returns': True
            },
            {
                'command': 'ping6 {destination} repetitions {count}',
                'doc': 'Send IPv6 ping',
                'arguments': [
                    {
                        'name': 'destination',
                        'doc': '<X:X::X:X> IPv6 address.'
                    },
                    {
                        'name': 'count',
                        'doc': 'Number of packets to send.'
                    }
                ],
                'returns': True
            },
            {
                'command': 'show ntp associations',
                'doc': 'Show NTP Association summary.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ntp authentication-key',
                'doc': 'Show NTP Authentication Keys information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ntp statistics',
                'doc': 'Show NTP Statistics information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ntp status',
                'doc': 'Show NTP Status information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ntp trusted-keys',
                'doc': 'Show NTP Trusted Keys information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show dhcp-server leases',
                'doc': 'Show DHCP server leases information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show dhcp-server',
                'doc': 'Display DHCP server configuration.',
                'arguments': [],
                'returns': True
            }
        ]
    }),
    ('configure', {
        'doc': 'Configuration terminal',
        'arguments': [],
        'pre_commands': ['configure terminal'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'no vlan {vlan_id}',
                'doc': 'Delete a VLAN',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': 'VLAN Identifier.',
                    },
                ],
            },
            {
                'command': 'no interface lag {lag_id}',
                'doc': 'Delete a lag',
                'arguments': [
                    {
                        'name': 'lag_id',
                        'doc': 'link-aggregation identifier.',
                    },
                ],
            },
            {
                'command': 'ip route {ipv4} {next_hop} {metric}',
                'doc': 'Configure static routes',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M IP destination prefix.',
                    },
                    {
                        'name': 'next_hop',
                        'doc': 'Can be an ip address or a interface.',
                    },
                    {
                        'name': 'metric',
                        'doc': 'Optional, route address to configure.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no ip route {ipv4} {next_hop} {metric}',
                'doc': 'Un-configure static routes',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M IP destination prefix.',
                    },
                    {
                        'name': 'next_hop',
                        'doc': 'Can be an ip address or a interface.',
                    },
                    {
                        'name': 'metric',
                        'doc': 'Optional, route address to configure.',
                        'optional': True
                    },
                ],
            },
            {
                'command': (
                    'ip prefix-list {prefix_name} seq {seq}'
                    ' {permission} {network}'
                ),
                'doc': 'Configure prefix list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  Name of a prefix list.',
                    },
                    {
                        'name': 'seq',
                        'doc': '<1-4294967295>  Sequence number.',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny    Specify packets to reject'
                            'permit  Specify packets to forward'
                        ),
                    },
                    {
                        'name': 'network',
                        'doc': (
                            'A.B.C.D/M  IP prefix <network>/<length>, e.g., '
                            '35.0.0.0/8 any Any prefix match. Same as '
                            '"0.0.0.0/0 le 32"'
                        ),
                    },
                ],
            },
            {
                'command': (
                    'no ip prefix-list {prefix_name} seq {seq}'
                    ' {permission} {network}'
                ),
                'doc': 'Un-configure prefix list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  Name of a prefix list.',
                    },
                    {
                        'name': 'seq',
                        'doc': '<1-4294967295>  Sequence number.',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny    Specify packets to reject'
                            'permit  Specify packets to forward'
                        ),
                    },
                    {
                        'name': 'network',
                        'doc': (
                            'A.B.C.D/M  IP prefix <network>/<length>, e.g., '
                            '35.0.0.0/8 any Any prefix match. Same as '
                            '"0.0.0.0/0 le 32"'
                        ),
                    },
                ],
            },
            {
                'command': (
                    'ipv6 prefix-list {prefix_name} seq {seq}'
                    ' {permission} {network}'
                ),
                'doc': 'Configure IPv6 prefix-based filtering',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  The IP prefix-list name',
                    },
                    {
                        'name': 'seq',
                        'doc': '<1-4294967295>  Sequence number',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny    Specify packets to reject'
                            'permit  Specify packets to forward'
                        ),
                    },
                    {
                        'name': 'network',
                        'doc': (
                            'X:X::X:X/M IPv6 prefix'
                        ),
                    },
                ],
            },
            {
                'command': (
                    'no ipv6 prefix-list {prefix_name} seq {seq}'
                    ' {permission} {network}'
                ),
                'doc': 'Deletes the IPv6 prefix-list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  The IP prefix-list name',
                    },
                    {
                        'name': 'seq',
                        'doc': '<1-4294967295>  Sequence number',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny    Specify packets to reject'
                            'permit  Specify packets to forward'
                        ),
                    },
                    {
                        'name': 'network',
                        'doc': (
                            'X:X::X:X/M IPv6 prefix'
                        ),
                    },
                ],
            },
            {
                'command': 'no route-map {routemap_name} {permission} {seq}',
                'doc': 'Route-map configuration',
                'arguments': [
                    {
                        'name': 'routemap_name',
                        'doc': 'WORD  Route map tag',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny  Route map denies set operations'
                            'permit  Route map permits set operations'
                        ),
                    },
                    {
                        'name': 'seq',
                        'doc': (
                            '<1-65535>  Sequence to insert to/delete from '
                            'existing route-map entry'
                        ),
                    },
                ],
            },
            {
                'command': 'ipv6 route {ipv6} {next_hop} {metric}',
                'doc': 'Configure static routes',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M IP destination prefix.',
                    },
                    {
                        'name': 'next_hop',
                        'doc': 'Can be an ip address or a interface.',
                    },
                    {
                        'name': 'metric',
                        'doc': 'Optional, route address to configure.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no ipv6 route {ipv6} {next_hop} {metric}',
                'doc': 'Un-configure static routes',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M IP destination prefix.',
                    },
                    {
                        'name': 'next_hop',
                        'doc': 'Can be an ip address or a interface.',
                    },
                    {
                        'name': 'metric',
                        'doc': 'Optional, route address to configure.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'lacp system-priority {priority}',
                'doc': 'Set LACP system priority.',
                'arguments': [
                    {
                        'name': 'priority',
                        'doc': '<0-65535>  The range is 0 to 65535.',
                    },
                ],
            },
            {
                'command': 'lldp enable',
                'doc': 'Enable LLDP globally.',
                'arguments': [],
            },
            {
                'command': 'no lldp enable',
                'doc': 'Disable LLDP globally.',
                'arguments': [],
            },
            {
                'command': 'sflow enable',
                'doc': 'Configure sFlow.',
                'arguments': [],
            },
            {
                'command': 'no sflow enable',
                'doc': 'Un-configure sFlow.',
                'arguments': [],
            },
            {
                'command': 'sflow sampling {rate}',
                'doc': 'Set sFlow sampling rate.',
                'arguments': [
                    {
                        'name': 'rate',
                        'doc': '<1-1000000000>  The range is 1 to 1000000000.',
                    }
                ],
            },
            {
                'command': 'no sflow sampling',
                'doc': 'Reset sFlow sampling rate to default.',
                'arguments': [],
            },
            {
                'command': (
                    'sflow agent-interface {port}'
                ),
                'doc': 'Set sFlow agent interface',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Valid L3 interface name.',
                    }
                ],
            },
            {
                'command': (
                    'sflow agent-interface {port} '
                    'agent-address-family {address_family}'
                ),
                'doc': 'Set sFlow agent interface and address family',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Valid L3 interface name.',
                    },
                    {
                        'name': 'address_family',
                        'doc': 'IPv4 or IPv6 (Default : IPv4).',
                    }
                ],
            },
            {
                'command': 'no sflow agent-interface',
                'doc': 'Remove sFlow agent interface configuration.',
                'arguments': [],
            },
            {
                'command': 'sflow collector {ip}',
                'doc': 'Set sFlow collector configuration (IP)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'IP address of collector.',
                    }
                ],
            },
            {
                'command': 'sflow collector {ip} port {port}',
                'doc': 'Set sFlow collector configuration (IP, port)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'IP address of collector.',
                    },
                    {
                        'name': 'port',
                        'doc': 'Port of collector <0-65535> (Default : 6343).',
                    }
                ],
            },
            {
                'command': 'sflow collector {ip} vrf {vrf}',
                'doc': 'Set sFlow collector configuration (IP, vrf)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'IP address of collector.',
                    },
                    {
                        'name': 'vrf',
                        'doc': 'Name of VRF (Default : vrf_default).',
                    }
                ],
            },
            {
                'command': 'sflow collector {ip} port {port} vrf {vrf}',
                'doc': 'Set sFlow collector configuration (IP, port, vrf)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'IP address of collector.',
                    },
                    {
                        'name': 'port',
                        'doc': 'Port of collector <0-65535> (Default : 6343).',
                    },
                    {
                        'name': 'vrf',
                        'doc': 'Name of VRF (Default : vrf_default).',
                    }
                ],
            },
            {
                'command': 'no router bgp {asn}',
                'doc': 'Removes the BGP Router',
                'arguments': [
                    {
                        'name': 'asn',
                        'doc': 'Autonomous System Number.',
                    }
                ],
            },
            {
                'command': 'ip ecmp disable',
                'doc': 'Completely disable ECMP',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp disable',
                'doc': 'Completely disable ECMP',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance dst-ip disable',
                'doc': 'Disable load balancing by destination IP',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance dst-ip disable',
                'doc': 'Disable load balancing by destination IP',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance dst-port disable',
                'doc': 'Disable load balancing by destination port',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance dst-port disable',
                'doc': 'Disable load balancing by destination port',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance src-port disable',
                'doc': 'Disable load balancing by source port',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance src-port disable',
                'doc': 'Disable load balancing by source port',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance src-ip disable',
                'doc': 'Disable load balancing by source IP',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance src-ip disable',
                'doc': 'Disable load balancing by source IP',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance resilient disable',
                'doc': 'Disable resilient hashing for load balancing',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance resilient disable',
                'doc': 'Disable resilient hashing for load balancing',
                'arguments': [],
            },
            {
                'command': 'ntp server {host}',
                'doc': 'NTP Association configuration',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    }
                ],
            },
            {
                'command': 'no ntp server {host}',
                'doc': 'Remove NTP association',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    }
                ],
            },
            {
                'command': 'ntp server {host} prefer',
                'doc': 'Add NTP Association preference configuration',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    }
                ],
            },
            {
                'command': 'ntp server {host} key-id {key_id}',
                'doc': 'Add NTP Key ID',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    },
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    }
                ],
            },
            {
                'command': 'ntp server {host} version {version}',
                'doc': 'Add NTP Association version configuration',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    },
                    {
                        'name': 'version',
                        'doc': 'WORD  Version can be 3 or 4',
                    }
                ],
            },
            {
                'command': 'ntp authentication enable',
                'doc': 'Enable NTP Authentication configuration',
                'arguments': [],
            },
            {
                'command': 'no ntp authentication enable',
                'doc': 'Disable NTP Authentication configuration',
                'arguments': [],
            },
            {
                'command': 'ntp authentication-key {key_id} md5 {password}',
                'doc': 'Add NTP Authentication Key',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    },
                    {
                        'name': 'password',
                        'doc': 'WORD  NTP MD5 Password <8-16> chars',
                    }
                ],
            },
            {
                'command': 'no ntp authentication-key {key_id}',
                'doc': 'Remove NTP Authentication Key',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    }
                ],
            },
            {
                'command': 'ntp trusted-key {key_id}',
                'doc': 'Add NTP Trusted Key',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    }
                ],
            },
            {
                'command': 'no ntp trusted-key {key_id}',
                'doc': 'Remove NTP Trusted Key',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    }
                ],
            },
            {
                'command': 'access-list ip {access_list}',
                'doc': 'Configure access list.',
                'arguments': [
                    {
                        'name': 'access_list',
                        'doc': 'Access List Name.',
                    },
                ],
            },
            {
                'command': 'no access-list ip {access_list}',
                'doc': 'Unconfigure access list.',
                'arguments': [
                    {
                        'name': 'access_list',
                        'doc': 'Access List Name.',
                    },
                ],
            },
            {
                'command': 'access-list ip {access_list} resequence'
                           ' {begin} {end}',
                'doc': 'Resequence ACL Lists.',
                'arguments': [
                    {
                        'name': 'access_list',
                        'doc': 'Access List Name.',
                    },
                    {
                        'name': 'begin',
                        'doc': 'beginning index of access list',
                    },
                    {
                        'name': 'end',
                        'doc': 'end index of access list',
                    },
                ],
            }
        ]
    }),
    ('route_map', {
        'doc': 'Route-map configuration',
        'arguments': [
            {
                'name': 'routemap_name',
                'doc': 'WORD  Route map tag',
            },
            {
                'name': 'permission',
                'doc': (
                    'deny  Route map denies set operations'
                    'permit  Route map permits set operations'
                ),
            },
            {
                'name': 'seq',
                'doc': (
                    'xr<1-65535>  Sequence to insert to/delete from existing '
                    'route-map entry'
                ),
            },
        ],
        'pre_commands': [
            'config terminal',
            'route-map {routemap_name} {permission} {seq}'
        ],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'description {description}',
                'doc': 'Set description',
                'arguments': [
                    {
                        'name': 'description',
                        'doc': 'LINE  Comment describing this route-map rule',
                    },
                ],
            },
            {
                'command': 'no description {description}',
                'doc': 'Unset description',
                'arguments': [
                    {
                        'name': 'description',
                        'doc': 'LINE  Comment describing this route-map rule',
                    },
                ],
            },
            {
                'command': 'match ip address prefix-list {prefix_name}',
                'doc': 'Set prefix-list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  IP prefix-list name',
                    },
                ],
            },
            {
                'command': 'no match ip address prefix-list {prefix_name}',
                'doc': 'Unset prefix-list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  IP prefix-list name',
                        'optional': True,
                    },
                ],
            },
            {
                'command': 'set metric {metric}',
                'doc': 'Set metric',
                'arguments': [
                    {
                        'name': 'metric',
                        'doc': '<0-4294967295>  Metric value',
                    },
                ],
            },
            {
                'command': 'no set metric {metric}',
                'doc': 'Unset metric',
                'arguments': [
                    {
                        'name': 'metric',
                        'doc': '<0-4294967295>  Metric value',
                        'optional': True,
                    },
                ],
            },
            {
                'command': 'set community {community}',
                'doc': 'Set community',
                'arguments': [
                    {
                        'name': 'community',
                        'doc': (
                            'AA:NN  Community number in aa:nn format or '
                            'local-AS\|no-advertise\|no-export\|internet or '
                            'additive'
                        ),
                    },
                ],
            },
            {
                'command': 'no set community {community}',
                'doc': 'Unset community',
                'arguments': [
                    {
                        'name': 'community',
                        'doc': (
                            'AA:NN  Community number in aa:nn format or'
                            'local-AS\|no-advertise\|no-export\|internet or '
                            'additive'
                        ),
                        'optional': True,
                    },
                ],
            },
        ],
    }),
    ('config_interface', {
        'doc': 'Interface configuration.',
        'arguments': [
            {
                'name': 'portlbl',
                'doc': 'Label that identifies an interface.'
            }
        ],
        'pre_commands': ['config terminal', 'interface {port}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip address {ipv4}',
                'doc': 'Set IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4}',
                'doc': 'Unset IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ip address {ipv4} secondary',
                'doc': 'Set secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4} secondary',
                'doc': 'Unset secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6}',
                'doc': 'Set IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6}',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6} secondary',
                'doc': 'Set secondary IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6} secondary',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'routing',
                'doc': 'Configure interface as L3.',
                'arguments': [],
            },
            {
                'command': 'no routing',
                'doc': 'Unconfigure interface as L3.',
                'arguments': [],
            },
            {
                'command': 'shutdown',
                'doc': 'Enable an interface.',
                'arguments': [],
            },
            {
                'command': 'no shutdown',
                'doc': 'Disable an interface.',
                'arguments': [],
            },
            {
                'command': 'vlan access {vlan_id}',
                'doc': 'Access configuration',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan access {vlan_id}',
                'doc': 'Remove vlan access',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'vlan trunk allowed {vlan_id}',
                'doc': 'Allow VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan trunk allowed {vlan_id}',
                'doc': 'Disallow VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'vlan trunk native tag',
                'doc': 'Tag configuration on the trunk port',
                'arguments': [],
            },
            {
                'command': 'no vlan trunk native tag',
                'doc': 'Remove tag configuration on the trunk port',
                'arguments': [],
            },
            {
                'command': 'vlan trunk native {vlan_id}',
                'doc': 'Native VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan trunk native {vlan_id}',
                'doc': 'Remove native VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'lacp port-id {port_id}',
                'doc': 'Set port ID used in LACP negotiation.',
                'arguments': [
                    {
                        'name': 'port_id',
                        'doc': '<1-65535>  .The range is 1 to 65535'
                    }
                ],
            },
            {
                'command': 'lacp port-priority {port_priority}',
                'doc': 'Set port priority is used in LACP negotiation.',
                'arguments': [
                    {
                        'name': 'port_priority',
                        'doc': '<1-65535>  The range is 1 to 65535'
                    }
                ],
            },
            {
                'command': 'lag {lag_id}',
                'doc': 'Add the current interface to link aggregation.',
                'arguments': [
                    {
                        'name': 'lag_id',
                        'doc': '<1-2000>  LAG number ranges from 1 to 2000'
                    }
                ],
            },
            {
                'command': 'no lag {lag_id}',
                'doc': 'Remove the current interface to link aggregation.',
                'arguments': [
                    {
                        'name': 'lag_id',
                        'doc': '<1-2000>  LAG number ranges from 1 to 2000'
                    }
                ],
            },
            {
                'command': 'lldp transmission',
                'doc': 'Set the transmission on lldp.',
                'arguments': [],
            },
            {
                'command': 'no lldp transmission',
                'doc': 'Un-set the transmission on lldp.',
                'arguments': [],
            },
            {
                'command': 'lldp reception',
                'doc': 'Set the reception on lldp.',
                'arguments': [],
            },
            {
                'command': 'no lldp reception',
                'doc': 'Un-set the reception on lldp.',
                'arguments': [],
            },
            {
                'command': 'udld enable',
                'doc': 'Enable UDLD in the interface.',
                'arguments': [],
            },
            {
                'command': 'no udld enable',
                'doc': 'Disable UDLD in the interface.',
                'arguments': [],
            },
            {
                'command': 'udld interval {interval}',
                'doc': 'Set the packet interval',
                'arguments': [
                    {
                        'name': 'interval',
                        'doc': '<100-10000> Allowed is 100 ms to 10,000 ms'
                    }
                ],
            },
            {
                'command': 'udld retries {retries}',
                'doc': 'Set the retries',
                'arguments': [
                    {
                        'name': 'retries',
                        'doc': '<3-10> Allowed is from 3 to 10 retries.'
                    }
                ],
            },
            {
                'command': 'udld mode {mode}',
                'doc': 'Set the operation mode',
                'arguments': [
                    {
                        'name': 'mode',
                        'doc': '<forward_then_verify | verify_then_forward>'
                    }
                ],
            },
            {
                'command': 'apply access-list ip {acl_name} in',
                'doc': 'Apply ACL on interface',
                'arguments': [
                    {
                        'name': 'acl_name',
                        'doc': 'Access-list name'
                    }
                ],
            },
            {
                'command': 'no apply access-list ip {acl_name} in',
                'doc': 'Apply no ACL on interface',
                'arguments': [
                    {
                        'name': 'acl_name',
                        'doc': 'Access-list name'
                    }
                ],
            },
        ]
    }),
    ('config_interface_vlan', {
        'doc': 'VLAN configuration.',
        'arguments': [
            {
                'name': 'vlan_id',
                'doc': 'Vlan id within <1-4094> and should not'
                       'be an internal vlan.'
            }
        ],
        'pre_commands': ['config terminal', 'interface vlan {vlan_id}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip address {ipv4}',
                'doc': 'Set IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4}',
                'doc': 'Unset IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ip address {ipv4} secondary',
                'doc': 'Set secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4} secondary',
                'doc': 'Unset secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6}',
                'doc': 'Set IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6}',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6} secondary',
                'doc': 'Set secondary IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6} secondary',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'shutdown',
                'doc': 'Enable an interface.',
                'arguments': [],
            },
            {
                'command': 'no shutdown',
                'doc': 'Disable an interface.',
                'arguments': [],
            },
        ]
    }),
    ('config_interface_loopback', {
        'doc': 'Loopback interface configuration.',
        'arguments': [
            {
                'name': 'loopback_id',
                'doc': 'Loopback  id within  range <1-2147483647> '
            }
        ],
        'pre_commands':
     ['config terminal', 'interface loopback {loopback_id}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip address {ipv4}',
                'doc': 'Set IPv4 address for loopback',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Loopback IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4}',
                'doc': 'Unset IPv4 address for loopback',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Loopback IP address.',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6}',
                'doc': 'Set IPv6 address on Loopback',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Loopback IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6}',
                'doc': 'Unset IPv6 address on loopback interface',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Loopback IPv6 address',
                    },
                ],
            },
        ]
     }),

    ('config_interface_lag', {
        'doc': 'Configure link-aggregation parameters.',
        'arguments': [
            {
                'name': 'lag',
                'doc': 'LAG number ranges from 1 to 2000.'
            }
        ],
        'pre_commands': ['config terminal', 'interface lag {lag}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip address {ipv4}',
                'doc': 'Set IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4}',
                'doc': 'Unset IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ip address {ipv4} secondary',
                'doc': 'Set secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4} secondary',
                'doc': 'Unset secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6}',
                'doc': 'Set IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6}',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6} secondary',
                'doc': 'Set secondary IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6} secondary',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'shutdown',
                'doc': 'Enable an interface.',
                'arguments': [],
            },
            {
                'command': 'no shutdown',
                'doc': 'Disable an interface.',
                'arguments': [],
            },
            {
                'command': 'routing',
                'doc': 'Configure interface as L3.',
                'arguments': [],
            },
            {
                'command': 'no routing',
                'doc': 'Unconfigure interface as L3.',
                'arguments': [],
            },
            {
                'command': 'vlan access {vlan_id}',
                'doc': 'Access configuration',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan access {vlan_id}',
                'doc': 'Remove vlan access',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'vlan trunk allowed {vlan_id}',
                'doc': 'Allow VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan trunk allowed {vlan_id}',
                'doc': 'Disallow VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'vlan trunk native tag',
                'doc': 'Tag configuration on the trunk port',
                'arguments': [],
            },
            {
                'command': 'no vlan trunk native tag',
                'doc': 'Remove tag configuration on the trunk port',
                'arguments': [],
            },
            {
                'command': 'vlan trunk native {vlan_id}',
                'doc': 'Native VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan trunk native {vlan_id}',
                'doc': 'Remove native VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'lacp mode passive',
                'doc': 'Sets an interface as LACP passive.',
                'arguments': [],
            },
            {
                'command': 'no lacp mode passive',
                'doc': 'Sets an LACP passive interface off.',
                'arguments': [],
            },
            {
                'command': 'lacp mode active',
                'doc': 'Sets an interface as LACP active.',
                'arguments': [],
            },
            {
                'command': 'no lacp mode active',
                'doc': 'Sets an LACP active interface off.',
                'arguments': [],
            },
            {
                'command': 'lacp fallback',
                'doc': 'Enable LACP fallback mode.',
                'arguments': [],
            },
            {
                'command': 'hash l2-src-dst',
                'doc': 'Base the hash on l2-src-dst.',
                'arguments': [],
            },
            {
                'command': 'hash l3-src-dst',
                'doc': 'Base the hash on l3-src-dst.',
                'arguments': [],
            },
            {
                'command': 'lacp rate fast',
                'doc': 'Set LACP heartbeats are requested at the rate '
                       'of one per second.',
                'arguments': [],
            },
            {
                'command': 'no lacp rate fast',
                'doc': 'Set LACP heartbeats slow which is once every '
                       ' 30 seconds.',
                'arguments': [],
            },
        ]
    }),
    ('config_interface_mgmt', {
        'doc': 'Configure management interface.',
        'arguments': [],
        'pre_commands': ['config terminal', 'interface mgmt'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip static {ip}',
                'doc': 'Set IP address',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'Interface IP (ipv4 or ipv6) address.',
                    },
                ],
            },
            {
                'command': 'no ip static {ip}',
                'doc': 'Unset IP address',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'Interface IP (ipv4 or ipv6) address.',
                    },
                ],
            },
            {
                'command': 'default-gateway {gateway}',
                'doc': 'Configure the Default gateway address (IPv4 and IPv6)',
                'arguments': [
                    {
                        'name': 'gateway',
                        'doc': 'IP (ipv4 or ipv6) address.',
                    },
                ],
            },
            {
                'command': 'no default-gateway {gateway}',
                'doc': 'Remove the Default gateway address (IPv4 and IPv6)',
                'arguments': [
                    {
                        'name': 'gateway',
                        'doc': 'IP (ipv4 or ipv6) address.',
                    },
                ],
            },
            {
                'command': 'nameserver {primary_nameserver} '
                           '{secondary_nameserver}',
                'doc': 'Configure the nameserver',
                'arguments': [
                    {
                        'name': 'primary_nameserver',
                        'doc': 'Primary nameserver (ipv4 or ipv6) address.',
                    },
                    {
                        'name': 'secondary_nameserver',
                        'doc': 'Secondary nameserver (ipv4 or ipv6) address.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no nameserver {primary_nameserver} '
                           '{secondary_nameserver}',
                'doc': 'Configure the nameserver',
                'arguments': [
                    {
                        'name': 'primary_nameserver',
                        'doc': 'Primary nameserver (ipv4 or ipv6) address.',
                    },
                    {
                        'name': 'secondary_nameserver',
                        'doc': 'Secondary nameserver (ipv4 or ipv6) address.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'ip dhcp',
                'doc': 'Set the mode as dhcp.',
                'arguments': [],
            },
        ]
    }),
    ('config_router_bgp', {
        'doc': 'BGP configuration.',
        'arguments': [
            {
                'name': 'asn',
                'doc': '<1-4294967295> AS number ranges from 1 to 4294967295'
            }
        ],
        'pre_commands': ['config terminal', 'router bgp {asn}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'bgp router-id {id}',
                'doc': 'Specifies the BGP router-ID for a BGP Router',
                'arguments': [
                    {
                        'name': 'id',
                        'doc': '<A.B.C.D> IPv4 address',
                    },
                ],
            },
            {
                'command': 'no bgp router-id {id}',
                'doc': 'Removes the BGP router-ID for a BGP Router',
                'arguments': [
                    {
                        'name': 'id',
                        'doc': '<A.B.C.D> IPv4 address',
                    },
                ],
            },
            {
                'command': 'bgp fast-external-failover',
                'doc': 'Immediately reset session if a link to '
                       'a directly connected external peer goes down',
                'arguments': [],
            },
            {
                'command': 'no bgp fast-external-failover',
                'doc': 'Disables BGP fast external failover',
                'arguments': [],
            },
            {
                'command': 'network {network}',
                'doc': 'Adds the announcement network for BGP',
                'arguments': [
                    {
                        'name': 'network',
                        'doc': '<A.B.C.D/M> IPv4 address with the prefix len',
                    },
                ],
            },
            {
                'command': 'no network {network}',
                'doc': 'Removes the announcement network for BGP',
                'arguments': [
                    {
                        'name': 'network',
                        'doc': '<A.B.C.D/M> IPv4 address'
                                ' with the prefix length',
                    },
                ],
            },
            {
                'command': 'maximum-paths {num}',
                'doc': 'Sets the maximum number of paths for a BGP route',
                'arguments': [
                    {
                        'name': 'num',
                        'doc': '<1-255> Maximum number of paths. Default is 1',
                    },
                ],
            },
            {
                'command': 'no maximum-paths {num}',
                'doc': 'Set the max number of paths to the default value of 1',
                'arguments': [
                    {
                        'name': 'num',
                        'doc': '<1-255> Maximum number of paths. Default is 1',
                    },
                ],
            },
            {
                'command': 'timers bgp {keepalive} {hold}',
                'doc': 'Sets the keepalive interval and hold time '
                       'for a BGP router',
                'arguments': [
                    {
                        'name': 'keepalive',
                        'doc': '<0-65535> Keepalive interval in seconds. '
                               'Default is 60',
                    },
                    {
                        'name': 'hold',
                        'doc': '<0 - 65535> Hold time in seconds. '
                               'Default is 180',
                    },
                ],
            },
            {
                'command': 'no timers bgp {keepalive} {hold}',
                'doc': 'Sets the default values for keepalive interval and '
                       'hold time for a BGP router',
                'arguments': [
                    {
                        'name': 'keepalive',
                        'doc': '<0 - 65535> Keepalive interval in seconds. '
                               'Default is 60',
                        'optional': True
                    },
                    {
                        'name': 'hold',
                        'doc': '<0 - 65535> Hold time in seconds. '
                               'Default is 180',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} remote-as {asn}',
                'doc': 'Configures a BGP neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'asn',
                        'doc': '<1 - 4294967295> Neighbor AS number. '
                               'Ranges from 1 to 4294967295',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip}',
                'doc': 'Removes a BGP neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip} route-map {route_name} {action}',
                'doc': 'Configures a BGP neighbor route-map',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'route_name',
                        'doc': 'WORD  Name of route map',
                    },
                    {
                        'name': 'action',
                        'doc': (
                            'export  Apply map to routes coming\n'
                            'from a Route-Server client\n'
                            'import  Apply map to routes going into\n'
                            'a Route-Server client\'s table\n'
                            'in      Apply map to incoming routes\n'
                            'out     Apply map to outbound routes\n'
                        ),
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} route-map {route_name} {action}',
                'doc': 'Unconfigures a BGP neighbor route-map',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'route_name',
                        'doc': 'WORD  Name of route map',
                    },
                    {
                        'name': 'action',
                        'doc': (
                            'export  Apply map to routes coming\n'
                            'from a Route-Server client\n'
                            'import  Apply map to routes going into\n'
                            'a Route-Server client\'s table\n'
                            'in      Apply map to incoming routes\n'
                            'out     Apply map to outbound routes\n'
                        ),
                    },
                ],
            },
            {
                'command': 'neighbor {peer} prefix-list {prefix_name} '
                           '{filter_direction}',
                'doc': 'Applies a prefix-list to the neighbor to filter '
                       'updates to and from the neighbor',
                'arguments': [
                    {
                        'name': 'peer',
                        'doc': '<A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address'
                               ' or neighbor tag',
                    },
                    {
                        'name': 'prefix_name',
                        'doc': '<WORD> The name of a prefix list',
                    },
                    {
                        'name': 'filter_direction',
                        'doc': '<in|out> Filters incoming/outgoing routes',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no neighbor {peer} prefix-list {prefix_name} '
                           '{filter_direction}',
                'doc': 'Remove a prefix-list filter from the neighbor',
                'arguments': [
                    {
                        'name': 'peer',
                        'doc': '<A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address'
                               ' or neighbor tag',
                    },
                    {
                        'name': 'prefix_name',
                        'doc': '<WORD> The name of a prefix list',
                    },
                    {
                        'name': 'filter_direction',
                        'doc': '<in|out> Filters incoming/outgoing routes',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} description {text}',
                'doc': 'Removes a BGP neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'text',
                        'doc': 'Description of the peer router. '
                               'String of maximum length 80 chars',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} description {text}',
                'doc': 'Removes a BGP neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'text',
                        'doc': (
                            'Description of the peer router.'
                            'String of maximum length 80 chars'
                        ),
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} password {pwd}',
                'doc': 'Enables MD5 authentication on a TCP connection '
                       'between BGP peers.',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'pwd',
                        'doc': (
                            'Password in plain text.'
                            'String of maximum length 80 chars'
                        ),
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} password',
                'doc': 'Removes MD5 authentication on a TCP connection '
                       'between BGP peers.',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip} timers {keepalive} {hold}',
                'doc': 'Sets the keepalive interval and hold time '
                       'for a specific BGP peer',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'keepalive',
                        'doc': (
                            '<0 - 65535> Keepalive interval in seconds.'
                            'Default is 60'
                        ),
                    },
                    {
                        'name': 'hold',
                        'doc': '<0-65535> Hold time in seconds. Default is 180'
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} timers {keepalive} {hold}',
                'doc': 'Sets the default values for keepalive interval '
                       'and hold time for a specific BGP peer',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'keepalive',
                        'doc': (
                            '<0 - 65535> Keepalive interval in seconds.'
                            'Default is 0'
                        ),
                        'optional': True
                    },
                    {
                        'name': 'hold',
                        'doc': '<0 - 65535> Hold time in seconds. '
                               'Default is 0',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} allowas-in {val}',
                'doc': 'Specifies an allow-as-in occurrence number '
                       'for an AS to be in the AS path',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'val',
                        'doc': (
                            '<0 - 10> Number of times BGP can allow an '
                            'instance of AS to be in the AS_PATH'
                        ),
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} allowas-in {val}',
                'doc': 'Clears the allow-as-in occurrence number for '
                       'an AS to be in the AS path',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'val',
                        'doc': (
                            '<0 - 10> Number of times BGP can allow an'
                            'instance of AS to be in the AS_PATH'
                        ),
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} remove-private-AS',
                'doc': (
                    'Removes private AS numbers from the AS path'
                    'in outbound routing updates'
                ),
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} remove-private-AS',
                'doc': 'Resets to a cleared state (default)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip} soft-reconfiguration inbound',
                'doc': 'Enables software-based reconfiguration to generate '
                       'updates from a neighbor without clearing the BGP '
                       'session',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} soft-reconfiguration inbound',
                'doc': 'Resets to a cleared state (default)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip} shutdown',
                'doc': (
                    'Shuts down the neighbor. This disables the peer router'
                    'but preserves neighbor configuration'
                ),
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} shutdown',
                'doc': 'Re-enables the neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip_or_group} peer-group {group}',
                'doc': 'Assigns a neighbor to a peer-group',
                'arguments': [
                    {
                        'name': 'ip_or_group',
                        'doc': (
                            '<A.B.C.D> Neighbor IPv4 address'
                            '<X:X::X:X> Neighbor IPv6 address'
                            '<WORD> Neighbor group'
                        ),
                    },
                    {
                        'name': 'group',
                        'doc': (
                            'Peer-group name.'
                            'String of maximum length 80 chars',
                        ),
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no neighbor {ip_or_group} peer-group {group}',
                'doc': 'Removes the neighbor from the peer-group',
                'arguments': [
                    {
                        'name': 'ip_or_group',
                        'doc': (
                            '<A.B.C.D> Neighbor IPv4 address'
                            '<X:X::X:X> Neighbor IPv6 address'
                            '<WORD> Neighbor group'
                        ),
                    },
                    {
                        'name': 'group',
                        'doc': 'Peer-group name. '
                               'String of maximum length 80 chars',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'redistribute {type}',
                'doc': 'Configures route redistribution of the '
                       'specified protocol into BGP',
                'arguments': [
                    {
                        'name': 'type',
                        'doc': (
                            '<connected | static | ospf>'
                        ),
                    },
                ],
            },
            {
                'command': 'no redistribute {type}',
                'doc': 'Unconfigures route redistribution of the '
                       'specified protocol into BGP',
                'arguments': [
                    {
                        'name': 'type',
                        'doc': (
                            '<connected | static | ospf>'
                        ),
                    },
                ],
            },
        ]
    }),
    ('config_vlan', {
        'doc': 'VLAN configuration.',
        'arguments': [
            {
                'name': 'vlan_id',
                'doc': '<1-4094>  VLAN identifier.'
            }
        ],
        'pre_commands': ['config terminal', 'vlan {vlan_id}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'shutdown',
                'doc': 'Enable the VLAN.',
                'arguments': [],
            },
            {
                'command': 'no shutdown',
                'doc': 'Disable the VLAN.',
                'arguments': [],
            },
            {
                'command': 'description {description}',
                'doc': 'Set VLAN description',
                'arguments': [
                    {
                        'name': 'description',
                        'doc': 'VLAN description.',
                    }
                ],
            },
            {
                'command': 'no description {description}',
                'doc': 'Un-set VLAN description',
                'arguments': [
                    {
                        'name': 'description',
                        'doc': 'VLAN description.',
                    }
                ],
            }
        ]
    },
    ),
    ('config_access_list_ip_testname', {
        'doc': 'ACE permission.',
        'arguments': [
            {
                'name': 'acl_name',
                'doc': 'access-list name'
            }
        ],
        'pre_commands': ['config terminal', 'access-list ip {acl_name}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': '{negate} {sequence} permit {protocol} '
                           '{ip1} {port1} {ip2} {port2} {count} {log}',
                'doc': 'Permit access-list entry',
                'arguments': [
                    {
                        'name': 'negate',
                        'doc': 'remove access-list entry.',
                    },
                    {
                        'name': 'sequence',
                        'doc': 'sequence number of ACE.',
                    },
                    {
                        'name': 'protocol',
                        'doc': 'Protocol (number) type.',
                    },
                    {
                        'name': 'ip1',
                        'doc': '<A.B.C.D/M> Source IPv4 address.',
                    },
                    {
                        'name': 'port1',
                        'doc': 'Source Port range <1-65535>.',
                    },
                    {
                        'name': 'ip2',
                        'doc': '<A.B.C.D/M> Destination IPv4 address.',
                    },
                    {
                        'name': 'port2',
                        'doc': 'Destination Port range <1-65535>.',
                    },
                    {
                        'name': 'count',
                        'doc': 'TBD',
                        'optional': True
                    },
                    {
                        'name': 'log',
                        'doc': 'TBD',
                        'optional': True
                    },
                ],
            },
            {
                'command': '{negate} {sequence} deny {protocol} '
                           '{ip1} {port1} {ip2} {port2} {count} {log}',
                'doc': 'Deny access-list entry',
                'arguments': [
                    {
                        'name': 'negate',
                        'doc': 'remove access-list entry.',
                    },
                    {
                        'name': 'sequence',
                        'doc': 'sequence number of ACE.',
                    },
                    {
                        'name': 'protocol',
                        'doc': 'Protocol type for entry.',
                    },
                    {
                        'name': 'ip1',
                        'doc': '<A.B.C.D/M> Source IPv4 address.',
                    },
                    {
                        'name': 'port1',
                        'doc': 'Source Port range <1-65535>.',
                    },
                    {
                        'name': 'ip2',
                        'doc': '<A.B.C.D/M> Destination IPv4 address.',
                    },
                    {
                        'name': 'port2',
                        'doc': 'Destination Port range <1-65535>.',
                    },
                    {
                        'name': 'count',
                        'doc': 'TBD',
                        'optional': True
                    },
                    {
                        'name': 'log',
                        'doc': 'TBD',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no {sequence}',
                'doc': 'Remove access-list entry',
                'arguments': [
                    {
                        'name': 'sequence',
                        'doc': 'sequence number of ACE.',
                    },
                ],
            },
        ]
    })
])

"""Vtysh Specification as a Python dictionary"""


VTYSH_EXCEPTIONS_SPEC = OrderedDict([
    (
        'UnknownCommandException',
        [
            'unknown command',
        ]
    ), (
        'IncompleteCommandException',
        [
            'command incomplete',
        ]
    ), (
        'InvalidQnCommandException',
        [
            'name  acl name',
        ]
    ), (
        'AclEmptyException',
        [
            'acl is empty',
        ]
    ), (
        'TcamResourcesException',
        [
            'command failed',
        ]
    ), (
        'ResequenceNumberException',
        [
            'sequence numbers would exceed maximum',
        ]
    ), (
        'AmbiguousCommandException',
        [
            'ambiguous command',
        ]
    ), (
        'InvalidL4SourcePortRangeException',
        [
            'invalid l4 source port range',
        ]
    ), (
        'EchoCommandException',
        [
            'range',
        ]
    ), (
        'AceDoesNotExistException',
        [
            'acl entry does not exist',
        ]
    ), (
        'AclDoesNotExistException',
        [
            'acl does not exist',
        ]
    )
])

"""Vtysh Exceptions specification as a Python dictionary"""


__all__ = ['VTYSH_SPEC', 'VTYSH_EXCEPTIONS_SPEC']
