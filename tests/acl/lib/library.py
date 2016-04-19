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
Vtysh auto-generated communication library module.

.. warning::

   This is auto-generated, do not modify manually!!
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from .parser import *  # noqa
from .exceptions import determine_exception


class ContextManager(object):
    """
    This class defines a context manager object.

    Usage:

    ::

        with ClassName(parameters) as ctx:
            ctx.first_function()
            ctx.second_function()

    This way at the beginning the **pre_commands** will be run and at the end
    the **post_commands** will clean the vtysh terminal. Every implementation
    of this class document their pre_commands and post_commands.

    """


class Configure(ContextManager):
    """
    Configuration terminal

    pre_commands:

    ::

            ['configure terminal']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode):
        self.enode = enode

    def __enter__(self):
        commands = """\
            configure terminal
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def no_vlan(
            self, vlan_id):
        """
        Delete a VLAN

        This function runs the following vtysh command:

        ::

            # no vlan {vlan_id}

        :param vlan_id: VLAN Identifier.
        """

        cmd = (
            'no vlan {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_interface_lag(
            self, lag_id):
        """
        Delete a lag

        This function runs the following vtysh command:

        ::

            # no interface lag {lag_id}

        :param lag_id: link-aggregation identifier.
        """

        cmd = (
            'no interface lag {lag_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_route(
            self, ipv4, next_hop, metric=''):
        """
        Configure static routes

        This function runs the following vtysh command:

        ::

            # ip route {ipv4} {next_hop} {metric}

        :param ipv4: A.B.C.D/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        """

        cmd = (
            'ip route {ipv4} {next_hop} {metric}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_route(
            self, ipv4, next_hop, metric=''):
        """
        Un-configure static routes

        This function runs the following vtysh command:

        ::

            # no ip route {ipv4} {next_hop} {metric}

        :param ipv4: A.B.C.D/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        """

        cmd = (
            'no ip route {ipv4} {next_hop} {metric}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_prefix_list_seq(
            self, prefix_name, seq, permission, network):
        """
        Configure prefix list

        This function runs the following vtysh command:

        ::

            # ip prefix-list {prefix_name} seq {seq} {permission} {network}

        :param prefix_name: WORD  Name of a prefix list.
        :param seq: <1-4294967295>  Sequence number.
        :param permission: deny    Specify packets to rejectpermit  Specify
            packets to forward
        :param network: A.B.C.D/M  IP prefix <network>/<length>, e.g.,
            35.0.0.0/8 any Any prefix match. Same as "0.0.0.0/0 le 32"
        """

        cmd = (
            'ip prefix-list {prefix_name} seq {seq} {permission} {network}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_prefix_list_seq(
            self, prefix_name, seq, permission, network):
        """
        Un-configure prefix list

        This function runs the following vtysh command:

        ::

            # no ip prefix-list {prefix_name} seq {seq} {permission} {network}

        :param prefix_name: WORD  Name of a prefix list.
        :param seq: <1-4294967295>  Sequence number.
        :param permission: deny    Specify packets to rejectpermit  Specify
            packets to forward
        :param network: A.B.C.D/M  IP prefix <network>/<length>, e.g.,
            35.0.0.0/8 any Any prefix match. Same as "0.0.0.0/0 le 32"
        """

        cmd = (
            'no ip prefix-list {prefix_name} seq {seq} {permission} {network}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ipv6_prefix_list_seq(
            self, prefix_name, seq, permission, network):
        """
        Configure IPv6 prefix-based filtering

        This function runs the following vtysh command:

        ::

            # ipv6 prefix-list {prefix_name} seq {seq} {permission} {network}

        :param prefix_name: WORD  The IP prefix-list name
        :param seq: <1-4294967295>  Sequence number
        :param permission: deny    Specify packets to rejectpermit  Specify
            packets to forward
        :param network: X:X::X:X/M IPv6 prefix
        """

        cmd = (
            'ipv6 prefix-list {prefix_name} seq {seq} {permission} {network}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_prefix_list_seq(
            self, prefix_name, seq, permission, network):
        """
        Deletes the IPv6 prefix-list

        This function runs the following vtysh command:

        ::

            # no ipv6 prefix-list {prefix_name} seq {seq} {permission} {network}  # noqa

        :param prefix_name: WORD  The IP prefix-list name
        :param seq: <1-4294967295>  Sequence number
        :param permission: deny    Specify packets to rejectpermit  Specify
            packets to forward
        :param network: X:X::X:X/M IPv6 prefix
        """

        cmd = (
            'no ipv6 prefix-list {prefix_name} seq {seq} {permission} '
            '{network}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_route_map(
            self, routemap_name, permission, seq):
        """
        Route-map configuration

        This function runs the following vtysh command:

        ::

            # no route-map {routemap_name} {permission} {seq}

        :param routemap_name: WORD  Route map tag
        :param permission: deny  Route map denies set operationspermit  Route
            map permits set operations
        :param seq: <1-65535>  Sequence to insert to/delete from existing
            route-map entry
        """

        cmd = (
            'no route-map {routemap_name} {permission} {seq}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ipv6_route(
            self, ipv6, next_hop, metric=''):
        """
        Configure static routes

        This function runs the following vtysh command:

        ::

            # ipv6 route {ipv6} {next_hop} {metric}

        :param ipv6: X:X::X:X/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        """

        cmd = (
            'ipv6 route {ipv6} {next_hop} {metric}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_route(
            self, ipv6, next_hop, metric=''):
        """
        Un-configure static routes

        This function runs the following vtysh command:

        ::

            # no ipv6 route {ipv6} {next_hop} {metric}

        :param ipv6: X:X::X:X/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        """

        cmd = (
            'no ipv6 route {ipv6} {next_hop} {metric}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lacp_system_priority(
            self, priority):
        """
        Set LACP system priority.

        This function runs the following vtysh command:

        ::

            # lacp system-priority {priority}

        :param priority: <0-65535>  The range is 0 to 65535.
        """

        cmd = (
            'lacp system-priority {priority}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lldp_enable(
            self):
        """
        Enable LLDP globally.

        This function runs the following vtysh command:

        ::

            # lldp enable

        """

        cmd = (
            'lldp enable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_lldp_enable(
            self):
        """
        Disable LLDP globally.

        This function runs the following vtysh command:

        ::

            # no lldp enable

        """

        cmd = (
            'no lldp enable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def sflow_enable(
            self):
        """
        Configure sFlow.

        This function runs the following vtysh command:

        ::

            # sflow enable

        """

        cmd = (
            'sflow enable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_sflow_enable(
            self):
        """
        Un-configure sFlow.

        This function runs the following vtysh command:

        ::

            # no sflow enable

        """

        cmd = (
            'no sflow enable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def sflow_sampling(
            self, rate):
        """
        Set sFlow sampling rate.

        This function runs the following vtysh command:

        ::

            # sflow sampling {rate}

        :param rate: <1-1000000000>  The range is 1 to 1000000000.
        """

        cmd = (
            'sflow sampling {rate}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_sflow_sampling(
            self):
        """
        Reset sFlow sampling rate to default.

        This function runs the following vtysh command:

        ::

            # no sflow sampling

        """

        cmd = (
            'no sflow sampling'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def sflow_agent_interface(
            self, portlbl):
        """
        Set sFlow agent interface

        This function runs the following vtysh command:

        ::

            # sflow agent-interface {port}

        :param portlbl: Valid L3 interface name.
        """
        port = self.enode.ports.get(portlbl, portlbl)

        cmd = (
            'sflow agent-interface {port}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def sflow_agent_interface_agent_address_family(
            self, portlbl, address_family):
        """
        Set sFlow agent interface and address family

        This function runs the following vtysh command:

        ::

            # sflow agent-interface {port} agent-address-family {address_family}  # noqa

        :param portlbl: Valid L3 interface name.
        :param address_family: IPv4 or IPv6 (Default : IPv4).
        """
        port = self.enode.ports.get(portlbl, portlbl)

        cmd = (
            'sflow agent-interface {port} agent-address-family '
            '{address_family}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_sflow_agent_interface(
            self):
        """
        Remove sFlow agent interface configuration.

        This function runs the following vtysh command:

        ::

            # no sflow agent-interface

        """

        cmd = (
            'no sflow agent-interface'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def sflow_collector(
            self, ip):
        """
        Set sFlow collector configuration (IP)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip}

        :param ip: IP address of collector.
        """

        cmd = (
            'sflow collector {ip}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def sflow_collector_port(
            self, ip, port):
        """
        Set sFlow collector configuration (IP, port)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip} port {port}

        :param ip: IP address of collector.
        :param port: Port of collector <0-65535> (Default : 6343).
        """

        cmd = (
            'sflow collector {ip} port {port}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def sflow_collector_vrf(
            self, ip, vrf):
        """
        Set sFlow collector configuration (IP, vrf)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip} vrf {vrf}

        :param ip: IP address of collector.
        :param vrf: Name of VRF (Default : vrf_default).
        """

        cmd = (
            'sflow collector {ip} vrf {vrf}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def sflow_collector_port_vrf(
            self, ip, port, vrf):
        """
        Set sFlow collector configuration (IP, port, vrf)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip} port {port} vrf {vrf}

        :param ip: IP address of collector.
        :param port: Port of collector <0-65535> (Default : 6343).
        :param vrf: Name of VRF (Default : vrf_default).
        """

        cmd = (
            'sflow collector {ip} port {port} vrf {vrf}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_router_bgp(
            self, asn):
        """
        Removes the BGP Router

        This function runs the following vtysh command:

        ::

            # no router bgp {asn}

        :param asn: Autonomous System Number.
        """

        cmd = (
            'no router bgp {asn}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_disable(
            self):
        """
        Completely disable ECMP

        This function runs the following vtysh command:

        ::

            # ip ecmp disable

        """

        cmd = (
            'ip ecmp disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_disable(
            self):
        """
        Completely disable ECMP

        This function runs the following vtysh command:

        ::

            # no ip ecmp disable

        """

        cmd = (
            'no ip ecmp disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_dst_ip_disable(
            self):
        """
        Disable load balancing by destination IP

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance dst-ip disable

        """

        cmd = (
            'ip ecmp load-balance dst-ip disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_dst_ip_disable(
            self):
        """
        Disable load balancing by destination IP

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance dst-ip disable

        """

        cmd = (
            'no ip ecmp load-balance dst-ip disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_dst_port_disable(
            self):
        """
        Disable load balancing by destination port

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance dst-port disable

        """

        cmd = (
            'ip ecmp load-balance dst-port disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_dst_port_disable(
            self):
        """
        Disable load balancing by destination port

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance dst-port disable

        """

        cmd = (
            'no ip ecmp load-balance dst-port disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_src_port_disable(
            self):
        """
        Disable load balancing by source port

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance src-port disable

        """

        cmd = (
            'ip ecmp load-balance src-port disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_src_port_disable(
            self):
        """
        Disable load balancing by source port

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance src-port disable

        """

        cmd = (
            'no ip ecmp load-balance src-port disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_src_ip_disable(
            self):
        """
        Disable load balancing by source IP

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance src-ip disable

        """

        cmd = (
            'ip ecmp load-balance src-ip disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_src_ip_disable(
            self):
        """
        Disable load balancing by source IP

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance src-ip disable

        """

        cmd = (
            'no ip ecmp load-balance src-ip disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_resilient_disable(
            self):
        """
        Disable resilient hashing for load balancing

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance resilient disable

        """

        cmd = (
            'ip ecmp load-balance resilient disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_resilient_disable(
            self):
        """
        Disable resilient hashing for load balancing

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance resilient disable

        """

        cmd = (
            'no ip ecmp load-balance resilient disable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ntp_server(
            self, host):
        """
        NTP Association configuration

        This function runs the following vtysh command:

        ::

            # ntp server {host}

        :param host: NTP Association name or IPv4 Address.
        """

        cmd = (
            'ntp server {host}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ntp_server(
            self, host):
        """
        Remove NTP association

        This function runs the following vtysh command:

        ::

            # no ntp server {host}

        :param host: NTP Association name or IPv4 Address.
        """

        cmd = (
            'no ntp server {host}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ntp_server_prefer(
            self, host):
        """
        Add NTP Association preference configuration

        This function runs the following vtysh command:

        ::

            # ntp server {host} prefer

        :param host: NTP Association name or IPv4 Address.
        """

        cmd = (
            'ntp server {host} prefer'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ntp_server_key_id(
            self, host, key_id):
        """
        Add NTP Key ID

        This function runs the following vtysh command:

        ::

            # ntp server {host} key-id {key_id}

        :param host: NTP Association name or IPv4 Address.
        :param key_id: WORD  NTP Key Number between 1-65534
        """

        cmd = (
            'ntp server {host} key-id {key_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ntp_server_version(
            self, host, version):
        """
        Add NTP Association version configuration

        This function runs the following vtysh command:

        ::

            # ntp server {host} version {version}

        :param host: NTP Association name or IPv4 Address.
        :param version: WORD  Version can be 3 or 4
        """

        cmd = (
            'ntp server {host} version {version}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ntp_authentication_enable(
            self):
        """
        Enable NTP Authentication configuration

        This function runs the following vtysh command:

        ::

            # ntp authentication enable

        """

        cmd = (
            'ntp authentication enable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ntp_authentication_enable(
            self):
        """
        Disable NTP Authentication configuration

        This function runs the following vtysh command:

        ::

            # no ntp authentication enable

        """

        cmd = (
            'no ntp authentication enable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ntp_authentication_key_md5(
            self, key_id, password):
        """
        Add NTP Authentication Key

        This function runs the following vtysh command:

        ::

            # ntp authentication-key {key_id} md5 {password}

        :param key_id: WORD  NTP Key Number between 1-65534
        :param password: WORD  NTP MD5 Password <8-16> chars
        """

        cmd = (
            'ntp authentication-key {key_id} md5 {password}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ntp_authentication_key(
            self, key_id):
        """
        Remove NTP Authentication Key

        This function runs the following vtysh command:

        ::

            # no ntp authentication-key {key_id}

        :param key_id: WORD  NTP Key Number between 1-65534
        """

        cmd = (
            'no ntp authentication-key {key_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ntp_trusted_key(
            self, key_id):
        """
        Add NTP Trusted Key

        This function runs the following vtysh command:

        ::

            # ntp trusted-key {key_id}

        :param key_id: WORD  NTP Key Number between 1-65534
        """

        cmd = (
            'ntp trusted-key {key_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ntp_trusted_key(
            self, key_id):
        """
        Remove NTP Trusted Key

        This function runs the following vtysh command:

        ::

            # no ntp trusted-key {key_id}

        :param key_id: WORD  NTP Key Number between 1-65534
        """

        cmd = (
            'no ntp trusted-key {key_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def access_list_ip(
            self, access_list):
        """
        Configure access list.

        This function runs the following vtysh command:

        ::

            # access-list ip {access_list}

        :param access_list: Access List Name.
        """

        cmd = (
            'access-list ip {access_list}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_access_list_ip(
            self, access_list):
        """
        Unconfigure access list.

        This function runs the following vtysh command:

        ::

            # no access-list ip {access_list}

        :param access_list: Access List Name.
        """

        cmd = (
            'no access-list ip {access_list}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def access_list_ip_resequence(
            self, access_list, begin, end):
        """
        Resequence ACL Lists.

        This function runs the following vtysh command:

        ::

            # access-list ip {access_list} resequence {begin} {end}

        :param access_list: Access List Name.
        :param begin: beginning index of access list
        :param end: end index of access list
        """

        cmd = (
            'access-list ip {access_list} resequence {begin} {end}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


class RouteMap(ContextManager):
    """
    Route-map configuration

    pre_commands:

    ::

            ['config terminal', 'route-map {routemap_name} {permission} {seq}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, routemap_name, permission, seq):
        self.enode = enode
        self.routemap_name = routemap_name
        self.permission = permission
        self.seq = seq

    def __enter__(self):
        commands = """\
            config terminal
            route-map {routemap_name} {permission} {seq}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def description(
            self, description):
        """
        Set description

        This function runs the following vtysh command:

        ::

            # description {description}

        :param description: LINE  Comment describing this route-map rule
        """

        cmd = (
            'description {description}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_description(
            self, description):
        """
        Unset description

        This function runs the following vtysh command:

        ::

            # no description {description}

        :param description: LINE  Comment describing this route-map rule
        """

        cmd = (
            'no description {description}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def match_ip_address_prefix_list(
            self, prefix_name):
        """
        Set prefix-list

        This function runs the following vtysh command:

        ::

            # match ip address prefix-list {prefix_name}

        :param prefix_name: WORD  IP prefix-list name
        """

        cmd = (
            'match ip address prefix-list {prefix_name}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_match_ip_address_prefix_list(
            self, prefix_name=''):
        """
        Unset prefix-list

        This function runs the following vtysh command:

        ::

            # no match ip address prefix-list {prefix_name}

        :param prefix_name: WORD  IP prefix-list name
        """

        cmd = (
            'no match ip address prefix-list {prefix_name}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def set_metric(
            self, metric):
        """
        Set metric

        This function runs the following vtysh command:

        ::

            # set metric {metric}

        :param metric: <0-4294967295>  Metric value
        """

        cmd = (
            'set metric {metric}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_set_metric(
            self, metric=''):
        """
        Unset metric

        This function runs the following vtysh command:

        ::

            # no set metric {metric}

        :param metric: <0-4294967295>  Metric value
        """

        cmd = (
            'no set metric {metric}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def set_community(
            self, community):
        """
        Set community

        This function runs the following vtysh command:

        ::

            # set community {community}

        :param community: AA:NN  Community number in aa:nn format or local-AS
            \|no-advertise\|no-export\|internet or additive
        """

        cmd = (
            'set community {community}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_set_community(
            self, community=''):
        """
        Unset community

        This function runs the following vtysh command:

        ::

            # no set community {community}

        :param community: AA:NN  Community number in aa:nn format orlocal-AS
            \|no-advertise\|no-export\|internet or additive
        """

        cmd = (
            'no set community {community}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


class ConfigInterface(ContextManager):
    """
    Interface configuration.

    pre_commands:

    ::

            ['config terminal', 'interface {port}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, portlbl):
        self.enode = enode
        self.port = enode.ports.get(portlbl, portlbl)

    def __enter__(self):
        commands = """\
            config terminal
            interface {port}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_address(
            self, ipv4):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'ip address {ipv4}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
            self, ipv4):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'no ip address {ipv4}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_address_secondary(
            self, ipv4):
        """
        Set secondary IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'ip address {ipv4} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_address_secondary(
            self, ipv4):
        """
        Unset secondary IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'no ip address {ipv4} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
            self, ipv6):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'ipv6 address {ipv6}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'no ipv6 address {ipv6}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ipv6_address_secondary(
            self, ipv6):
        """
        Set secondary IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'ipv6 address {ipv6} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address_secondary(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'no ipv6 address {ipv6} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def routing(
            self):
        """
        Configure interface as L3.

        This function runs the following vtysh command:

        ::

            # routing

        """

        cmd = (
            'routing'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_routing(
            self):
        """
        Unconfigure interface as L3.

        This function runs the following vtysh command:

        ::

            # no routing

        """

        cmd = (
            'no routing'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def shutdown(
            self):
        """
        Enable an interface.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = (
            'shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Disable an interface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = (
            'no shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def vlan_access(
            self, vlan_id):
        """
        Access configuration

        This function runs the following vtysh command:

        ::

            # vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'vlan access {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_vlan_access(
            self, vlan_id):
        """
        Remove vlan access

        This function runs the following vtysh command:

        ::

            # no vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'no vlan access {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_allowed(
            self, vlan_id):
        """
        Allow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'vlan trunk allowed {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_allowed(
            self, vlan_id):
        """
        Disallow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'no vlan trunk allowed {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native_tag(
            self):
        """
        Tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native tag

        """

        cmd = (
            'vlan trunk native tag'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native_tag(
            self):
        """
        Remove tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native tag

        """

        cmd = (
            'no vlan trunk native tag'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native(
            self, vlan_id):
        """
        Native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'vlan trunk native {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native(
            self, vlan_id):
        """
        Remove native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'no vlan trunk native {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lacp_port_id(
            self, port_id):
        """
        Set port ID used in LACP negotiation.

        This function runs the following vtysh command:

        ::

            # lacp port-id {port_id}

        :param port_id: <1-65535>  .The range is 1 to 65535
        """

        cmd = (
            'lacp port-id {port_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lacp_port_priority(
            self, port_priority):
        """
        Set port priority is used in LACP negotiation.

        This function runs the following vtysh command:

        ::

            # lacp port-priority {port_priority}

        :param port_priority: <1-65535>  The range is 1 to 65535
        """

        cmd = (
            'lacp port-priority {port_priority}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lag(
            self, lag_id):
        """
        Add the current interface to link aggregation.

        This function runs the following vtysh command:

        ::

            # lag {lag_id}

        :param lag_id: <1-2000>  LAG number ranges from 1 to 2000
        """

        cmd = (
            'lag {lag_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_lag(
            self, lag_id):
        """
        Remove the current interface to link aggregation.

        This function runs the following vtysh command:

        ::

            # no lag {lag_id}

        :param lag_id: <1-2000>  LAG number ranges from 1 to 2000
        """

        cmd = (
            'no lag {lag_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lldp_transmission(
            self):
        """
        Set the transmission on lldp.

        This function runs the following vtysh command:

        ::

            # lldp transmission

        """

        cmd = (
            'lldp transmission'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_lldp_transmission(
            self):
        """
        Un-set the transmission on lldp.

        This function runs the following vtysh command:

        ::

            # no lldp transmission

        """

        cmd = (
            'no lldp transmission'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lldp_reception(
            self):
        """
        Set the reception on lldp.

        This function runs the following vtysh command:

        ::

            # lldp reception

        """

        cmd = (
            'lldp reception'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_lldp_reception(
            self):
        """
        Un-set the reception on lldp.

        This function runs the following vtysh command:

        ::

            # no lldp reception

        """

        cmd = (
            'no lldp reception'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def udld_enable(
            self):
        """
        Enable UDLD in the interface.

        This function runs the following vtysh command:

        ::

            # udld enable

        """

        cmd = (
            'udld enable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_udld_enable(
            self):
        """
        Disable UDLD in the interface.

        This function runs the following vtysh command:

        ::

            # no udld enable

        """

        cmd = (
            'no udld enable'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def udld_interval(
            self, interval):
        """
        Set the packet interval

        This function runs the following vtysh command:

        ::

            # udld interval {interval}

        :param interval: <100-10000> Allowed is 100 ms to 10,000 ms
        """

        cmd = (
            'udld interval {interval}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def udld_retries(
            self, retries):
        """
        Set the retries

        This function runs the following vtysh command:

        ::

            # udld retries {retries}

        :param retries: <3-10> Allowed is from 3 to 10 retries.
        """

        cmd = (
            'udld retries {retries}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def udld_mode(
            self, mode):
        """
        Set the operation mode

        This function runs the following vtysh command:

        ::

            # udld mode {mode}

        :param mode: <forward_then_verify | verify_then_forward>
        """

        cmd = (
            'udld mode {mode}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def apply_access_list_ip_in(
            self, acl_name):
        """
        Apply ACL on interface

        This function runs the following vtysh command:

        ::

            # apply access-list ip {acl_name} in

        :param acl_name: Access-list name
        """

        cmd = (
            'apply access-list ip {acl_name} in'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_apply_access_list_ip_in(
            self, acl_name):
        """
        Apply no ACL on interface

        This function runs the following vtysh command:

        ::

            # no apply access-list ip {acl_name} in

        :param acl_name: Access-list name
        """

        cmd = (
            'no apply access-list ip {acl_name} in'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


class ConfigInterfaceVlan(ContextManager):
    """
    VLAN configuration.

    pre_commands:

    ::

            ['config terminal', 'interface vlan {vlan_id}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, vlan_id):
        self.enode = enode
        self.vlan_id = vlan_id

    def __enter__(self):
        commands = """\
            config terminal
            interface vlan {vlan_id}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_address(
            self, ipv4):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'ip address {ipv4}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
            self, ipv4):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'no ip address {ipv4}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_address_secondary(
            self, ipv4):
        """
        Set secondary IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'ip address {ipv4} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_address_secondary(
            self, ipv4):
        """
        Unset secondary IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'no ip address {ipv4} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
            self, ipv6):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'ipv6 address {ipv6}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'no ipv6 address {ipv6}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ipv6_address_secondary(
            self, ipv6):
        """
        Set secondary IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'ipv6 address {ipv6} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address_secondary(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'no ipv6 address {ipv6} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def shutdown(
            self):
        """
        Enable an interface.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = (
            'shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Disable an interface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = (
            'no shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


class ConfigInterfaceLoopback(ContextManager):
    """
    Loopback interface configuration.

    pre_commands:

    ::

            ['config terminal', 'interface loopback {loopback_id}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, loopback_id):
        self.enode = enode
        self.loopback_id = loopback_id

    def __enter__(self):
        commands = """\
            config terminal
            interface loopback {loopback_id}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_address(
            self, ipv4):
        """
        Set IPv4 address for loopback

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Loopback IP address.
        """

        cmd = (
            'ip address {ipv4}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
            self, ipv4):
        """
        Unset IPv4 address for loopback

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Loopback IP address.
        """

        cmd = (
            'no ip address {ipv4}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
            self, ipv6):
        """
        Set IPv6 address on Loopback

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Loopback IPv6 address
        """

        cmd = (
            'ipv6 address {ipv6}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
            self, ipv6):
        """
        Unset IPv6 address on loopback interface

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Loopback IPv6 address
        """

        cmd = (
            'no ipv6 address {ipv6}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


class ConfigInterfaceLag(ContextManager):
    """
    Configure link-aggregation parameters.

    pre_commands:

    ::

            ['config terminal', 'interface lag {lag}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, lag):
        self.enode = enode
        self.lag = lag

    def __enter__(self):
        commands = """\
            config terminal
            interface lag {lag}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_address(
            self, ipv4):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'ip address {ipv4}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
            self, ipv4):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'no ip address {ipv4}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_address_secondary(
            self, ipv4):
        """
        Set secondary IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'ip address {ipv4} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_address_secondary(
            self, ipv4):
        """
        Unset secondary IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = (
            'no ip address {ipv4} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
            self, ipv6):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'ipv6 address {ipv6}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'no ipv6 address {ipv6}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ipv6_address_secondary(
            self, ipv6):
        """
        Set secondary IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'ipv6 address {ipv6} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address_secondary(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = (
            'no ipv6 address {ipv6} secondary'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def shutdown(
            self):
        """
        Enable an interface.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = (
            'shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Disable an interface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = (
            'no shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def routing(
            self):
        """
        Configure interface as L3.

        This function runs the following vtysh command:

        ::

            # routing

        """

        cmd = (
            'routing'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_routing(
            self):
        """
        Unconfigure interface as L3.

        This function runs the following vtysh command:

        ::

            # no routing

        """

        cmd = (
            'no routing'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def vlan_access(
            self, vlan_id):
        """
        Access configuration

        This function runs the following vtysh command:

        ::

            # vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'vlan access {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_vlan_access(
            self, vlan_id):
        """
        Remove vlan access

        This function runs the following vtysh command:

        ::

            # no vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'no vlan access {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_allowed(
            self, vlan_id):
        """
        Allow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'vlan trunk allowed {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_allowed(
            self, vlan_id):
        """
        Disallow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'no vlan trunk allowed {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native_tag(
            self):
        """
        Tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native tag

        """

        cmd = (
            'vlan trunk native tag'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native_tag(
            self):
        """
        Remove tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native tag

        """

        cmd = (
            'no vlan trunk native tag'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native(
            self, vlan_id):
        """
        Native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'vlan trunk native {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native(
            self, vlan_id):
        """
        Remove native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = (
            'no vlan trunk native {vlan_id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lacp_mode_passive(
            self):
        """
        Sets an interface as LACP passive.

        This function runs the following vtysh command:

        ::

            # lacp mode passive

        """

        cmd = (
            'lacp mode passive'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_lacp_mode_passive(
            self):
        """
        Sets an LACP passive interface off.

        This function runs the following vtysh command:

        ::

            # no lacp mode passive

        """

        cmd = (
            'no lacp mode passive'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lacp_mode_active(
            self):
        """
        Sets an interface as LACP active.

        This function runs the following vtysh command:

        ::

            # lacp mode active

        """

        cmd = (
            'lacp mode active'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_lacp_mode_active(
            self):
        """
        Sets an LACP active interface off.

        This function runs the following vtysh command:

        ::

            # no lacp mode active

        """

        cmd = (
            'no lacp mode active'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lacp_fallback(
            self):
        """
        Enable LACP fallback mode.

        This function runs the following vtysh command:

        ::

            # lacp fallback

        """

        cmd = (
            'lacp fallback'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def hash_l2_src_dst(
            self):
        """
        Base the hash on l2-src-dst.

        This function runs the following vtysh command:

        ::

            # hash l2-src-dst

        """

        cmd = (
            'hash l2-src-dst'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def hash_l3_src_dst(
            self):
        """
        Base the hash on l3-src-dst.

        This function runs the following vtysh command:

        ::

            # hash l3-src-dst

        """

        cmd = (
            'hash l3-src-dst'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def lacp_rate_fast(
            self):
        """
        Set LACP heartbeats are requested at the rate of one per second.

        This function runs the following vtysh command:

        ::

            # lacp rate fast

        """

        cmd = (
            'lacp rate fast'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_lacp_rate_fast(
            self):
        """
        Set LACP heartbeats slow which is once every  30 seconds.

        This function runs the following vtysh command:

        ::

            # no lacp rate fast

        """

        cmd = (
            'no lacp rate fast'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


class ConfigInterfaceMgmt(ContextManager):
    """
    Configure management interface.

    pre_commands:

    ::

            ['config terminal', 'interface mgmt']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode):
        self.enode = enode

    def __enter__(self):
        commands = """\
            config terminal
            interface mgmt
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_static(
            self, ip):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip static {ip}

        :param ip: Interface IP (ipv4 or ipv6) address.
        """

        cmd = (
            'ip static {ip}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_ip_static(
            self, ip):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip static {ip}

        :param ip: Interface IP (ipv4 or ipv6) address.
        """

        cmd = (
            'no ip static {ip}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def default_gateway(
            self, gateway):
        """
        Configure the Default gateway address (IPv4 and IPv6)

        This function runs the following vtysh command:

        ::

            # default-gateway {gateway}

        :param gateway: IP (ipv4 or ipv6) address.
        """

        cmd = (
            'default-gateway {gateway}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_default_gateway(
            self, gateway):
        """
        Remove the Default gateway address (IPv4 and IPv6)

        This function runs the following vtysh command:

        ::

            # no default-gateway {gateway}

        :param gateway: IP (ipv4 or ipv6) address.
        """

        cmd = (
            'no default-gateway {gateway}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def nameserver(
            self, primary_nameserver, secondary_nameserver=''):
        """
        Configure the nameserver

        This function runs the following vtysh command:

        ::

            # nameserver {primary_nameserver} {secondary_nameserver}

        :param primary_nameserver: Primary nameserver (ipv4 or ipv6) address.
        :param secondary_nameserver: Secondary nameserver (ipv4 or ipv6)
            address.
        """

        cmd = (
            'nameserver {primary_nameserver} {secondary_nameserver}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_nameserver(
            self, primary_nameserver, secondary_nameserver=''):
        """
        Configure the nameserver

        This function runs the following vtysh command:

        ::

            # no nameserver {primary_nameserver} {secondary_nameserver}

        :param primary_nameserver: Primary nameserver (ipv4 or ipv6) address.
        :param secondary_nameserver: Secondary nameserver (ipv4 or ipv6)
            address.
        """

        cmd = (
            'no nameserver {primary_nameserver} {secondary_nameserver}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def ip_dhcp(
            self):
        """
        Set the mode as dhcp.

        This function runs the following vtysh command:

        ::

            # ip dhcp

        """

        cmd = (
            'ip dhcp'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


class ConfigRouterBgp(ContextManager):
    """
    BGP configuration.

    pre_commands:

    ::

            ['config terminal', 'router bgp {asn}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, asn):
        self.enode = enode
        self.asn = asn

    def __enter__(self):
        commands = """\
            config terminal
            router bgp {asn}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def bgp_router_id(
            self, id):
        """
        Specifies the BGP router-ID for a BGP Router

        This function runs the following vtysh command:

        ::

            # bgp router-id {id}

        :param id: <A.B.C.D> IPv4 address
        """

        cmd = (
            'bgp router-id {id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_bgp_router_id(
            self, id):
        """
        Removes the BGP router-ID for a BGP Router

        This function runs the following vtysh command:

        ::

            # no bgp router-id {id}

        :param id: <A.B.C.D> IPv4 address
        """

        cmd = (
            'no bgp router-id {id}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def bgp_fast_external_failover(
            self):
        """
        Immediately reset session if a link to a directly connected external
        peer goes down

        This function runs the following vtysh command:

        ::

            # bgp fast-external-failover

        """

        cmd = (
            'bgp fast-external-failover'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_bgp_fast_external_failover(
            self):
        """
        Disables BGP fast external failover

        This function runs the following vtysh command:

        ::

            # no bgp fast-external-failover

        """

        cmd = (
            'no bgp fast-external-failover'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def network(
            self, network):
        """
        Adds the announcement network for BGP

        This function runs the following vtysh command:

        ::

            # network {network}

        :param network: <A.B.C.D/M> IPv4 address with the prefix len
        """

        cmd = (
            'network {network}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_network(
            self, network):
        """
        Removes the announcement network for BGP

        This function runs the following vtysh command:

        ::

            # no network {network}

        :param network: <A.B.C.D/M> IPv4 address with the prefix length
        """

        cmd = (
            'no network {network}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def maximum_paths(
            self, num):
        """
        Sets the maximum number of paths for a BGP route

        This function runs the following vtysh command:

        ::

            # maximum-paths {num}

        :param num: <1-255> Maximum number of paths. Default is 1
        """

        cmd = (
            'maximum-paths {num}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_maximum_paths(
            self, num):
        """
        Set the max number of paths to the default value of 1

        This function runs the following vtysh command:

        ::

            # no maximum-paths {num}

        :param num: <1-255> Maximum number of paths. Default is 1
        """

        cmd = (
            'no maximum-paths {num}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def timers_bgp(
            self, keepalive, hold):
        """
        Sets the keepalive interval and hold time for a BGP router

        This function runs the following vtysh command:

        ::

            # timers bgp {keepalive} {hold}

        :param keepalive: <0-65535> Keepalive interval in seconds. Default is
            60
        :param hold: <0 - 65535> Hold time in seconds. Default is 180
        """

        cmd = (
            'timers bgp {keepalive} {hold}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_timers_bgp(
            self, keepalive='', hold=''):
        """
        Sets the default values for keepalive interval and hold time for a BGP
        router

        This function runs the following vtysh command:

        ::

            # no timers bgp {keepalive} {hold}

        :param keepalive: <0 - 65535> Keepalive interval in seconds. Default
            is 60
        :param hold: <0 - 65535> Hold time in seconds. Default is 180
        """

        cmd = (
            'no timers bgp {keepalive} {hold}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_remote_as(
            self, ip, asn):
        """
        Configures a BGP neighbor

        This function runs the following vtysh command:

        ::

            # neighbor {ip} remote-as {asn}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param asn: <1 - 4294967295> Neighbor AS number. Ranges from 1 to
            4294967295
        """

        cmd = (
            'neighbor {ip} remote-as {asn}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor(
            self, ip):
        """
        Removes a BGP neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {ip}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = (
            'no neighbor {ip}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_route_map(
            self, ip, route_name, action):
        """
        Configures a BGP neighbor route-map

        This function runs the following vtysh command:

        ::

            # neighbor {ip} route-map {route_name} {action}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param route_name: WORD  Name of route map
        :param action: export  Apply map to routes coming
            from a Route-Server
            client
            import  Apply map to routes going into
            a Route-Server client's
            table
            in      Apply map to incoming routes
            out     Apply map to
            outbound routes
        """

        cmd = (
            'neighbor {ip} route-map {route_name} {action}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_route_map(
            self, ip, route_name, action):
        """
        Unconfigures a BGP neighbor route-map

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} route-map {route_name} {action}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param route_name: WORD  Name of route map
        :param action: export  Apply map to routes coming
            from a Route-Server
            client
            import  Apply map to routes going into
            a Route-Server client's
            table
            in      Apply map to incoming routes
            out     Apply map to
            outbound routes
        """

        cmd = (
            'no neighbor {ip} route-map {route_name} {action}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_prefix_list(
            self, peer, prefix_name, filter_direction=''):
        """
        Applies a prefix-list to the neighbor to filter updates to and from the
        neighbor

        This function runs the following vtysh command:

        ::

            # neighbor {peer} prefix-list {prefix_name} {filter_direction}

        :param peer: <A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address or
            neighbor tag
        :param prefix_name: <WORD> The name of a prefix list
        :param filter_direction: <in|out> Filters incoming/outgoing routes
        """

        cmd = (
            'neighbor {peer} prefix-list {prefix_name} {filter_direction}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_prefix_list(
            self, peer, prefix_name, filter_direction=''):
        """
        Remove a prefix-list filter from the neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {peer} prefix-list {prefix_name} {filter_direction}

        :param peer: <A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address or
            neighbor tag
        :param prefix_name: <WORD> The name of a prefix list
        :param filter_direction: <in|out> Filters incoming/outgoing routes
        """

        cmd = (
            'no neighbor {peer} prefix-list {prefix_name} {filter_direction}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_description(
            self, ip, text):
        """
        Removes a BGP neighbor

        This function runs the following vtysh command:

        ::

            # neighbor {ip} description {text}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param text: Description of the peer router. String of maximum length
            80 chars
        """

        cmd = (
            'neighbor {ip} description {text}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_description(
            self, ip, text=''):
        """
        Removes a BGP neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} description {text}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param text: Description of the peer router.String of maximum length
            80 chars
        """

        cmd = (
            'no neighbor {ip} description {text}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_password(
            self, ip, pwd):
        """
        Enables MD5 authentication on a TCP connection between BGP peers.

        This function runs the following vtysh command:

        ::

            # neighbor {ip} password {pwd}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param pwd: Password in plain text.String of maximum length 80 chars
        """

        cmd = (
            'neighbor {ip} password {pwd}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_password(
            self, ip):
        """
        Removes MD5 authentication on a TCP connection between BGP peers.

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} password

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = (
            'no neighbor {ip} password'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_timers(
            self, ip, keepalive, hold):
        """
        Sets the keepalive interval and hold time for a specific BGP peer

        This function runs the following vtysh command:

        ::

            # neighbor {ip} timers {keepalive} {hold}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param keepalive: <0 - 65535> Keepalive interval in seconds.Default is
            60
        :param hold: <0-65535> Hold time in seconds. Default is 180
        """

        cmd = (
            'neighbor {ip} timers {keepalive} {hold}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_timers(
            self, ip, keepalive='', hold=''):
        """
        Sets the default values for keepalive interval and hold time for a
        specific BGP peer

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} timers {keepalive} {hold}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param keepalive: <0 - 65535> Keepalive interval in seconds.Default is
            0
        :param hold: <0 - 65535> Hold time in seconds. Default is 0
        """

        cmd = (
            'no neighbor {ip} timers {keepalive} {hold}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_allowas_in(
            self, ip, val=''):
        """
        Specifies an allow-as-in occurrence number for an AS to be in the AS
        path

        This function runs the following vtysh command:

        ::

            # neighbor {ip} allowas-in {val}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param val: <0 - 10> Number of times BGP can allow an instance of AS
            to be in the AS_PATH
        """

        cmd = (
            'neighbor {ip} allowas-in {val}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_allowas_in(
            self, ip, val=''):
        """
        Clears the allow-as-in occurrence number for an AS to be in the AS path

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} allowas-in {val}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param val: <0 - 10> Number of times BGP can allow aninstance of AS to
            be in the AS_PATH
        """

        cmd = (
            'no neighbor {ip} allowas-in {val}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_remove_private_as(
            self, ip):
        """
        Removes private AS numbers from the AS pathin outbound routing updates

        This function runs the following vtysh command:

        ::

            # neighbor {ip} remove-private-AS

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = (
            'neighbor {ip} remove-private-AS'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_remove_private_as(
            self, ip):
        """
        Resets to a cleared state (default)

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} remove-private-AS

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = (
            'no neighbor {ip} remove-private-AS'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_soft_reconfiguration_inbound(
            self, ip):
        """
        Enables software-based reconfiguration to generate updates from a
        neighbor without clearing the BGP session

        This function runs the following vtysh command:

        ::

            # neighbor {ip} soft-reconfiguration inbound

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = (
            'neighbor {ip} soft-reconfiguration inbound'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_soft_reconfiguration_inbound(
            self, ip):
        """
        Resets to a cleared state (default)

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} soft-reconfiguration inbound

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = (
            'no neighbor {ip} soft-reconfiguration inbound'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_shutdown(
            self, ip):
        """
        Shuts down the neighbor. This disables the peer routerbut preserves
        neighbor configuration

        This function runs the following vtysh command:

        ::

            # neighbor {ip} shutdown

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = (
            'neighbor {ip} shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_shutdown(
            self, ip):
        """
        Re-enables the neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} shutdown

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = (
            'no neighbor {ip} shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def neighbor_peer_group(
            self, ip_or_group, group=''):
        """
        Assigns a neighbor to a peer-group

        This function runs the following vtysh command:

        ::

            # neighbor {ip_or_group} peer-group {group}

        :param ip_or_group: <A.B.C.D> Neighbor IPv4 address<X:X::X:X> Neighbor
            IPv6 address<WORD> Neighbor group
        :param group: ('Peer-group name.String of maximum length 80 chars',)
        """

        cmd = (
            'neighbor {ip_or_group} peer-group {group}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_peer_group(
            self, ip_or_group, group=''):
        """
        Removes the neighbor from the peer-group

        This function runs the following vtysh command:

        ::

            # no neighbor {ip_or_group} peer-group {group}

        :param ip_or_group: <A.B.C.D> Neighbor IPv4 address<X:X::X:X> Neighbor
            IPv6 address<WORD> Neighbor group
        :param group: Peer-group name. String of maximum length 80 chars
        """

        cmd = (
            'no neighbor {ip_or_group} peer-group {group}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def redistribute(
            self, type):
        """
        Configures route redistribution of the specified protocol into BGP

        This function runs the following vtysh command:

        ::

            # redistribute {type}

        :param type: <connected | static | ospf>
        """

        cmd = (
            'redistribute {type}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_redistribute(
            self, type):
        """
        Unconfigures route redistribution of the specified protocol into BGP

        This function runs the following vtysh command:

        ::

            # no redistribute {type}

        :param type: <connected | static | ospf>
        """

        cmd = (
            'no redistribute {type}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


class ConfigVlan(ContextManager):
    """
    VLAN configuration.

    pre_commands:

    ::

            ['config terminal', 'vlan {vlan_id}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, vlan_id):
        self.enode = enode
        self.vlan_id = vlan_id

    def __enter__(self):
        commands = """\
            config terminal
            vlan {vlan_id}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def shutdown(
            self):
        """
        Enable the VLAN.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = (
            'shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Disable the VLAN.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = (
            'no shutdown'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def description(
            self, description):
        """
        Set VLAN description

        This function runs the following vtysh command:

        ::

            # description {description}

        :param description: VLAN description.
        """

        cmd = (
            'description {description}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no_description(
            self, description):
        """
        Un-set VLAN description

        This function runs the following vtysh command:

        ::

            # no description {description}

        :param description: VLAN description.
        """

        cmd = (
            'no description {description}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


class ConfigAccessListIpTestname(ContextManager):
    """
    ACE permission.

    pre_commands:

    ::

            ['config terminal', 'access-list ip {acl_name}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, acl_name):
        self.enode = enode
        self.acl_name = acl_name

    def __enter__(self):
        commands = """\
            config terminal
            access-list ip {acl_name}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def permit(
            self, negate, sequence, protocol, ip1, port1, ip2,
            port2, count='', log=''):
        """
        Permit access-list entry

        This function runs the following vtysh command:

        ::

            # {negate} {sequence} permit {protocol} {ip1} {port1} {ip2} {port2} {count} {log}  # noqa

        :param negate: remove access-list entry.
        :param sequence: sequence number of ACE.
        :param protocol: Protocol (number) type.
        :param ip1: <A.B.C.D/M> Source IPv4 address.
        :param port1: Source Port range <1-65535>.
        :param ip2: <A.B.C.D/M> Destination IPv4 address.
        :param port2: Destination Port range <1-65535>.
        :param count: TBD
        :param log: TBD
        """  # noqa

        cmd = (
            '{negate} {sequence} permit {protocol} {ip1} {port1} {ip2} '
            '{port2} {count} {log}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def deny(
            self, negate, sequence, protocol, ip1, port1, ip2,
            port2, count='', log=''):
        """
        Deny access-list entry

        This function runs the following vtysh command:

        ::

            # {negate} {sequence} deny {protocol} {ip1} {port1} {ip2} {port2} {count} {log}  # noqa

        :param negate: remove access-list entry.
        :param sequence: sequence number of ACE.
        :param protocol: Protocol type for entry.
        :param ip1: <A.B.C.D/M> Source IPv4 address.
        :param port1: Source Port range <1-65535>.
        :param ip2: <A.B.C.D/M> Destination IPv4 address.
        :param port2: Destination Port range <1-65535>.
        :param count: TBD
        :param log: TBD
        """  # noqa

        cmd = (
            '{negate} {sequence} deny {protocol} {ip1} {port1} {ip2} {port2} '
            '{count} {log}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)

    def no(
            self, sequence):
        """
        Remove access-list entry

        This function runs the following vtysh command:

        ::

            # no {sequence}

        :param sequence: sequence number of ACE.
        """

        cmd = (
            'no {sequence}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        if result:
            raise determine_exception(result)(result)


def show_interface(
        enode, portlbl):
    """
    Interface infomation.

    This function runs the following vtysh command:

    ::

        # show interface {port}

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface`
    """
    port = enode.ports.get(portlbl, portlbl)

    cmd = (
        'show interface {port}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_interface(result)


def show_vlan(
        enode, vlanid=''):
    """
    Show VLAN configuration.

    This function runs the following vtysh command:

    ::

        # show vlan {vlanid}

    :param vlanid: Vlan ID number.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlan`
    """

    cmd = (
        'show vlan {vlanid}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_vlan(result)


def show_lacp_interface(
        enode, portlbl):
    """
    Show LACP interface.

    This function runs the following vtysh command:

    ::

        # show lacp interface {port}

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lacp_interface`
    """
    port = enode.ports.get(portlbl, portlbl)

    cmd = (
        'show lacp interface {port}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_lacp_interface(result)


def show_lacp_aggregates(
        enode, lag=''):
    """
    Show LACP aggregates.

    This function runs the following vtysh command:

    ::

        # show lacp aggregates {lag}

    :param lag: Link-aggregate name.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lacp_aggregates`
    """

    cmd = (
        'show lacp aggregates {lag}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_lacp_aggregates(result)


def show_lacp_configuration(
        enode):
    """
    Show LACP configuration.

    This function runs the following vtysh command:

    ::

        # show lacp configuration

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lacp_configuration`
    """

    cmd = (
        'show lacp configuration'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_lacp_configuration(result)


def show_lldp_neighbor_info(
        enode, portlbl):
    """
    Show global LLDP neighbor information.

    This function runs the following vtysh command:

    ::

        # show lldp neighbor-info {port}

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lldp_neighbor_info`
    """
    port = enode.ports.get(portlbl, portlbl)

    cmd = (
        'show lldp neighbor-info {port}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_lldp_neighbor_info(result)


def show_lldp_statistics(
        enode):
    """
    Show LLDP statistics.

    This function runs the following vtysh command:

    ::

        # show lldp statistics

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lldp_statistics`
    """

    cmd = (
        'show lldp statistics'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_lldp_statistics(result)


def show_ip_bgp_summary(
        enode):
    """
    Show bgp neighbors information summary.

    This function runs the following vtysh command:

    ::

        # show ip bgp summary

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp_summary`
    """

    cmd = (
        'show ip bgp summary'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ip_bgp_summary(result)


def show_ip_bgp_neighbors(
        enode):
    """
    Show bgp neighbors information.

    This function runs the following vtysh command:

    ::

        # show ip bgp neighbors

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp_neighbors`
    """

    cmd = (
        'show ip bgp neighbors'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ip_bgp_neighbors(result)


def show_ip_bgp(
        enode):
    """
    Show bgp routing information.

    This function runs the following vtysh command:

    ::

        # show ip bgp

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp`
    """

    cmd = (
        'show ip bgp'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ip_bgp(result)


def show_ipv6_bgp(
        enode):
    """
    Show bgp routing information.

    This function runs the following vtysh command:

    ::

        # show ipv6 bgp

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ipv6_bgp`
    """

    cmd = (
        'show ipv6 bgp'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ipv6_bgp(result)


def show_running_config(
        enode):
    """
    Show running-config information.

    This function runs the following vtysh command:

    ::

        # show running-config

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_running_config`
    """

    cmd = (
        'show running-config'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_running_config(result)


def show_ip_route(
        enode):
    """
    Show Routing Table.

    This function runs the following vtysh command:

    ::

        # show ip route

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_route`
    """

    cmd = (
        'show ip route'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ip_route(result)


def show_ipv6_route(
        enode):
    """
    Display the routing table.

    This function runs the following vtysh command:

    ::

        # show ipv6 route

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ipv6_route`
    """

    cmd = (
        'show ipv6 route'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ipv6_route(result)


def show_udld_interface(
        enode, portlbl):
    """
    Show UDLD information for the interface.

    This function runs the following vtysh command:

    ::

        # show udld interface {port}

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_udld_interface`
    """
    port = enode.ports.get(portlbl, portlbl)

    cmd = (
        'show udld interface {port}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_udld_interface(result)


def show_rib(
        enode):
    """
    Show Routing Information Base.

    This function runs the following vtysh command:

    ::

        # show rib

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_rib`
    """

    cmd = (
        'show rib'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_rib(result)


def show_ip_ecmp(
        enode):
    """
    Show ECMP Configuration

    This function runs the following vtysh command:

    ::

        # show ip ecmp

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ecmp`
    """

    cmd = (
        'show ip ecmp'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ip_ecmp(result)


def clear_udld_statistics(
        enode):
    """
    Clear UDLD statistics from all interfaces.

    This function runs the following vtysh command:

    ::

        # clear udld statistics

    """

    cmd = (
        'clear udld statistics'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    if result:
        raise determine_exception(result)(result)


def clear_udld_statistics_interface(
        enode, portlbl):
    """
    Clear UDLD statistics for the interface.

    This function runs the following vtysh command:

    ::

        # clear udld statistics interface {port}

    :param portlbl: Label that identifies interface.
    """
    port = enode.ports.get(portlbl, portlbl)

    cmd = (
        'clear udld statistics interface {port}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    if result:
        raise determine_exception(result)(result)


def ping_repetitions(
        enode, destination, count):
    """
    Send IPv4 ping

    This function runs the following vtysh command:

    ::

        # ping {destination} repetitions {count}

    :param destination: <A.B.C.D> IPv4 address.
    :param count: Number of packets to send.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_ping_repetitions`
    """

    cmd = (
        'ping {destination} repetitions {count}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_ping_repetitions(result)


def ping6_repetitions(
        enode, destination, count):
    """
    Send IPv6 ping

    This function runs the following vtysh command:

    ::

        # ping6 {destination} repetitions {count}

    :param destination: <X:X::X:X> IPv6 address.
    :param count: Number of packets to send.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_ping6_repetitions`
    """

    cmd = (
        'ping6 {destination} repetitions {count}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_ping6_repetitions(result)


def show_ntp_associations(
        enode):
    """
    Show NTP Association summary.

    This function runs the following vtysh command:

    ::

        # show ntp associations

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_associations`
    """

    cmd = (
        'show ntp associations'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ntp_associations(result)


def show_ntp_authentication_key(
        enode):
    """
    Show NTP Authentication Keys information.

    This function runs the following vtysh command:

    ::

        # show ntp authentication-key

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_authentication_key`
    """

    cmd = (
        'show ntp authentication-key'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ntp_authentication_key(result)


def show_ntp_statistics(
        enode):
    """
    Show NTP Statistics information.

    This function runs the following vtysh command:

    ::

        # show ntp statistics

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_statistics`
    """

    cmd = (
        'show ntp statistics'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ntp_statistics(result)


def show_ntp_status(
        enode):
    """
    Show NTP Status information.

    This function runs the following vtysh command:

    ::

        # show ntp status

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_status`
    """

    cmd = (
        'show ntp status'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ntp_status(result)


def show_ntp_trusted_keys(
        enode):
    """
    Show NTP Trusted Keys information.

    This function runs the following vtysh command:

    ::

        # show ntp trusted-keys

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_trusted_keys`
    """

    cmd = (
        'show ntp trusted-keys'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_ntp_trusted_keys(result)


def show_dhcp_server_leases(
        enode):
    """
    Show DHCP server leases information.

    This function runs the following vtysh command:

    ::

        # show dhcp-server leases

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_dhcp_server_leases`
    """

    cmd = (
        'show dhcp-server leases'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_dhcp_server_leases(result)


def show_dhcp_server(
        enode):
    """
    Display DHCP server configuration.

    This function runs the following vtysh command:

    ::

        # show dhcp-server

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_dhcp_server`
    """

    cmd = (
        'show dhcp-server'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    return parse_show_dhcp_server(result)


__all__ = [
    'ContextManager',
    'Configure',
    'RouteMap',
    'ConfigInterface',
    'ConfigInterfaceVlan',
    'ConfigInterfaceLoopback',
    'ConfigInterfaceLag',
    'ConfigInterfaceMgmt',
    'ConfigRouterBgp',
    'ConfigVlan',
    'ConfigAccessListIpTestname',
    'show_interface',
    'show_vlan',
    'show_lacp_interface',
    'show_lacp_aggregates',
    'show_lacp_configuration',
    'show_lldp_neighbor_info',
    'show_lldp_statistics',
    'show_ip_bgp_summary',
    'show_ip_bgp_neighbors',
    'show_ip_bgp',
    'show_ipv6_bgp',
    'show_running_config',
    'show_ip_route',
    'show_ipv6_route',
    'show_udld_interface',
    'show_rib',
    'show_ip_ecmp',
    'clear_udld_statistics',
    'clear_udld_statistics_interface',
    'ping_repetitions',
    'ping6_repetitions',
    'show_ntp_associations',
    'show_ntp_authentication_key',
    'show_ntp_statistics',
    'show_ntp_status',
    'show_ntp_trusted_keys',
    'show_dhcp_server_leases',
    'show_dhcp_server'
]
