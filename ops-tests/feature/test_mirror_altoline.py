# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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
OpenSwitch Mirror Routed Traffic
"""

from time import sleep

from pytest import mark

TOPOLOGY = """
#                +---------+
#                |         |
#                |   sn1   |
#                |         |
#                +----+----+
#                     |
# +---------+         |          +---------+
# |         |    +----+----+     |         |
# |   hs1   +----+   ops1  +-----+   hs2   |
# |         |    +---------+     |         |
# +---------+                    +---------+
#
# Nodes

[type=openswitch name="OpenSwitch 1"] ops1

[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2
[type=host name="Sniffer 1" image="openswitch/ubuntuscapy:latest"] sn1

# Links
hs1:if01 -- ops1:if01
hs2:if01 -- ops1:if02
sn1:if01 -- ops1:if06
"""
# Variables that are used alot
hs1_ip_info = {'ip': '10.10.10.1', 'ip_mask': '10.10.10.1/24'}
hs2_ip_info = {'ip': '10.10.11.1', 'ip_mask': '10.10.11.1/24'}
sn1_ip_info = {'ip': '10.10.12.1', 'ip_mask': '10.10.12.1/24'}

prt1_ip_info = {'ip': '10.10.10.2', 'ip_mask': '10.10.10.2/24'}
prt2_ip_info = {'ip': '10.10.11.2', 'ip_mask': '10.10.11.2/24'}
prt6_ip_info = {'ip': '10.10.12.2', 'ip_mask': '10.10.12.2/24'}

scapy_sniff_command = ""

switch_mac_addr = ""
default_ttl = 65


get_host_mac_command = "ifconfig {} | awk '/HWaddr/ {{print $5}}'"

which_test = 'vlan'


@mark.timeout(1200)
@mark.platform_incompatible(['docker'])
def test_mirror_routing(topology):
    global which_test
    which_test = 'routing'
    setup_topology(topology, 'hw')


@mark.gate
@mark.platform_incompatible(['ostl'])
def test_mirror_vlan_docker(topology):
    global which_test
    which_test = 'vlan'
    setup_topology(topology, 'docker')


@mark.timeout(1200)
@mark.platform_incompatible(['docker'])
def test_mirror_vlan_hw(topology):
    global which_test
    which_test = 'vlan'
    setup_topology(topology, 'hw')


def setup_topology(topology, platform):
    assert topology is not None
    ops = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    sn1 = topology.get('sn1')

    global scapy_sniff_command
    scapy_sniff_command = "echo \'sniff(iface=\"{}\"," \
                          "filter=\"icmp\"," \
                          "prn=lambda x:x.sprintf(\"" \
                          "{{ICMP:ICMPType=%ICMP.type% }}" \
                          "{{IP:srcIP=%IP.src% dstIP=%IP.dst% " \
                          "ttl=%IP.ttl% }}{{Ether:ethSrc=%Ether.src% " \
                          "ethDst=%Ether.dst%}}\"), timeout=5)\' | "\
                          "scapy 2>/dev/null".format(sn1.ports['if01'])

    if(which_test == 'vlan'):
        # Change global that is used for routing and vlan test. Need to make
        # hs2 on same subnet as hs1 for this test. By default they are set
        # to be on seperate subnets (routing test requires different subnets)
        hs2_ip_info['ip'] = '10.10.10.2'
        hs2_ip_info['ip_mask'] = '10.10.10.2/24'

    # Configure IP and bring UP host 1 interfaces
    hs1.libs.ip.interface('if01', addr=hs1_ip_info['ip_mask'], up=True)

    # Configure IP and bring UP host 2 interfaces
    hs2.libs.ip.interface('if01', addr=hs2_ip_info['ip_mask'], up=True)

    # Configure IP and bring UP sniffer 1 interfaces
    ifg = "ifconfig {} promisc".format(sn1.ports['if01'])
    sn1.send_command(ifg, shell='bash')
    sn1.libs.ip.interface('if01', addr=sn1_ip_info['ip_mask'], up=True)
    sn1.send_command('sudo apt-get install scapy', shell='bash')

    if(which_test == 'vlan'):
        configure_vlan(ops, platform)
    elif(which_test == 'routing'):
        configure_routes(ops, hs1, hs2, platform)
    else:
        assert False, "Invalid which_test option"

    # Set Mac Addresses. We don't use MAC addresses for the
    # vlan test but we set it so we don't get any errors and
    # we can use the same test for both routing and vlan
    hs1_ip_info['macAddr'] = hs1.send_command(
                                get_host_mac_command.format(hs1.ports['if01']),
                                shell='bash')
    hs2_ip_info['macAddr'] = hs2.send_command(
                                get_host_mac_command.format(hs2.ports['if01']),
                                shell='bash')
    sn1_ip_info['macAddr'] = sn1.send_command(
                                get_host_mac_command.format(sn1.ports['if01']),
                                shell='bash')
    # All interfaces should have the same MAC address
    global switch_mac_addr
    switch_mac_addr = ops.libs.vtysh.show_interface('if01')['mac_address']
    print("Switch MAC addr " + switch_mac_addr)

    shutdown_mirror_if01_config(ops)
    shutdown_mirror_if02_config(ops)
    shutdown_dual_source_mirror(ops)

    run_mirror_test(ops, hs1, hs2, sn1)


def configure_routes(ops, hs1, hs2, platform):
    # Configure IP and bring UP switch 1 interfaces
    with ops.libs.vtysh.ConfigInterface('if01') as ctx:
        ctx.ip_address(prt1_ip_info['ip_mask'])
        ctx.no_shutdown()

    with ops.libs.vtysh.ConfigInterface('if02') as ctx:
        ctx.ip_address(prt2_ip_info['ip_mask'])
        ctx.no_shutdown()

    with ops.libs.vtysh.ConfigInterface('if06') as ctx:
        ctx.no_shutdown()

    # Set gateway in hosts
    hs1.libs.ip.add_route('default', prt1_ip_info['ip'])
    hs2.libs.ip.add_route('default', prt2_ip_info['ip'])


def configure_vlan(ops, platform):
    # Configure Vlans
    with ops.libs.vtysh.ConfigVlan('100') as ctx:
        ctx.no_shutdown()

    with ops.libs.vtysh.ConfigVlan('200') as ctx:
        ctx.no_shutdown()

    # Bring UP switch 1 interfaces
    with ops.libs.vtysh.ConfigInterface('if01') as ctx:
        ctx.no_routing()
        ctx.vlan_access(100)
        ctx.no_shutdown()

    with ops.libs.vtysh.ConfigInterface('if02') as ctx:
        ctx.no_routing()
        ctx.vlan_access(100)
        ctx.no_shutdown()
    with ops.libs.vtysh.ConfigInterface('if06') as ctx:
        # This if-block is used to configure vlan for docker only
        # because when this was written HW didn't support the destination
        # interface to have any configuration besides 'no shutdown'
        if(platform == 'docker'):
            ctx.no_routing()
            ctx.vlan_access(200)
        ctx.no_shutdown()


def run_mirror_test(ops, hs1, hs2, sn1):
    # Disclaimer:
    # Dest and src mac addresses and TTl have no meaning for VLAN test
    # they are only valid for Routing test.

    global which_test
    print("#########################################")
    print("Test case 1 - hs1->hs2, rx mirror on if01")
    print("#########################################")
    # Setup mirror
    mirror_if01_config(ops, direction='rx')

    # Only expect request packets from hs1
    start_ping(hs1, hs2_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')

    stop_ping(hs1)
    print(packets)

    passed = False
    for index, packet in enumerate(packets.split('\n')):
        # Ignore first packet, it is formated bad because of how
        # scapy returns the output
        if index == 0 or "ICMPType" not in packet:
            continue
        data = get_packet_data(packet)
        print(str(data))
        # Dest and src mac addresses and ttl have no meaning for VLAN test
        # Ignore the checks for the VLAN test
        if which_test == 'vlan':
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP'] and hs2_ip_info['ip'] ==
                   data['dstIP']):
                    passed = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP'] and hs2_ip_info['ip'] ==
                   data['dstIP'] and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr and data['ttl'] ==
                   str(default_ttl)):
                    passed = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet

    assert passed, "didn't receive expected packet "
    packets = ""

    # Shutdown Other Mirror
    shutdown_mirror_if01_config(ops)

    print("##############################################################")
    print("Test case 2- hs1->hs2 and hs2->hs1, rx mirror on if01 and if02")
    print("##############################################################")
    # Two Source Ports in mirror. Expect Ping Requests from both hosts
    dual_source_mirror(ops, direction_s1='rx', direction_s2='rx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs1, hs2_ip_info)
    start_ping(hs2, hs1_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)
    stop_ping(hs2)

    print(packets)
    h1_request = False
    h1_reply = False
    h2_request = False
    h2_reply = False
    for index, packet in enumerate(packets.split('\n')):
        # Ignore first packet, it is formated bad because of how
        # scapy returns the output
        if index == 0 or "ICMPType" not in packet:
            continue
        data = get_packet_data(packet)
        print(str(data))
        # Dest and src mac addresses and ttl have no meaning for VLAN test
        # Ignore the checks for the VLAN test
        if which_test == 'vlan':
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_request = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_reply = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h1_request = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs2_ip_info['macAddr']
                     and data['ethDst'] == switch_mac_addr
                     and data['ttl'] == str(default_ttl)):
                    h2_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl - 1)):
                    h1_reply = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs2_ip_info['macAddr']
                     and data['ethDst'] == switch_mac_addr
                     and data['ttl'] == str(default_ttl - 1)):
                    h2_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet

    assert h1_request, "didn't get Host 1 ping request packets" + packets
    assert h2_request, "didn't get Host 2 ping request packets" + packets
    assert h1_reply, "didn't get Host 1 ping reply packets" + packets
    assert h2_reply, "didn't get Host 2 ping reply packets" + packets
    packets = ""

    # Shutdown other Mirror
    shutdown_dual_source_mirror(ops)

    print("##########################################")
    print("Test case 3 - hs1->hs2 , tx mirror on if01")
    print("##########################################")
    # Setup mirror
    mirror_if01_config(ops, direction='tx')
    print("Waiting for 2 secs")
    sleep(2)

    # Testing Tx, only expect reply packets from hs2
    start_ping(hs1, hs2_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)
    print(packets)
    h2_reply = False
    for index, packet in enumerate(packets.split('\n')):
        # Ignore first packet, it is formated bad because of how
        # scapy returns the output
        if index == 0 or "ICMPType" not in packet:
            continue
        data = get_packet_data(packet)
        print(str(data))
        # Dest and src mac addresses and ttl have no meaning for VLAN test
        # Ignore the checks for the VLAN test
        if which_test == 'vlan':
            if data['ICMPType'] == 'echo-reply':
                if(hs2_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h2_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-reply':
                if(hs2_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == switch_mac_addr
                   and data['ethDst'] == hs1_ip_info['macAddr']
                   and data['ttl'] == str(default_ttl - 2)):
                    h2_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet

    assert h2_reply, "didn't get Host 2 ping reply packets" + packets
    packets = ""

    # Shutdown Other Mirror
    shutdown_mirror_if01_config(ops)

    print("###############################################################")
    print("Test case 4 - hs1->hs2 and hs2->hs1, tx mirror on if01 and if02")
    print("###############################################################")
    # Two Source Ports in mirror.
    dual_source_mirror(ops, direction_s1='tx', direction_s2='tx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs1, hs2_ip_info)
    start_ping(hs2, hs1_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)
    stop_ping(hs2)

    h1_request = False
    h1_reply = False
    h2_request = False
    h2_reply = False
    print(packets)
    for index, packet in enumerate(packets.split('\n')):
        # Ignore first packet, it is formated bad because of how
        # scapy returns the output
        if index == 0 or "ICMPType" not in packet:
            continue
        data = get_packet_data(packet)
        print(str(data))
        # Dest and src mac addresses and ttl have no meaning for VLAN test
        # Ignore the checks for the VLAN test
        if which_test == 'vlan':
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_request = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_reply = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == switch_mac_addr
                   and data['ethDst'] == hs2_ip_info['macAddr']
                   and data['ttl'] == str(default_ttl - 1)):
                    h1_request = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h2_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == switch_mac_addr
                   and data['ethDst'] == hs2_ip_info['macAddr']
                   and data['ttl'] == str(default_ttl - 2)):
                    h1_reply = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 2)):
                    h2_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h1_request, "didn't get Host 1 ping request packets" + packets
    assert h2_request, "didn't get Host 2 ping request packets" + packets
    assert h1_reply, "didn't get Host 1 ping reply packets" + packets
    assert h2_reply, "didn't get Host 2 ping reply packets" + packets
    packets = ""

    # ShutDown other mirror
    shutdown_dual_source_mirror(ops)

    print("###########################################")
    print("Test case 5 - hs1->hs2, both mirror on if01")
    print("###########################################")
    # Setup mirror
    mirror_if01_config(ops, direction='both')
    print("Waiting for 2 secs")
    sleep(2)

    # Testing 'both' so expect requests from h1 and replies from h2
    start_ping(hs1, hs2_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)

    h1_request = False
    h2_reply = False
    print(packets)
    for index, packet in enumerate(packets.split('\n')):
        # Ignore first packet, it is formated bad because of how
        # scapy returns the output
        if index == 0 or "ICMPType" not in packet:
            continue
        data = get_packet_data(packet)
        print(str(data))
        # Dest and src mac addresses and ttl have no meaning for VLAN test
        # Ignore the checks for the VLAN test
        if which_test == 'vlan':
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs2_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h2_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h1_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs2_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == switch_mac_addr
                   and data['ethDst'] == hs1_ip_info['macAddr']
                   and data['ttl'] == str(default_ttl - 2)):
                    h2_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet

    assert h1_request, "didn't get Host 1 ping request packets" + packets
    assert h2_reply, "didn't get Host 2 ping reply packets" + packets
    packets = ""

    # Shutdown Other Mirror
    shutdown_mirror_if01_config(ops)

    print("#################################################################")
    print("Test case 6 - hs1->hs2 and hs2->hs1, both mirror on if01 and if02")
    print("#################################################################")
    # Two Source Ports in mirror.
    dual_source_mirror(ops, direction_s1='both', direction_s2='both')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs1, hs2_ip_info)
    start_ping(hs2, hs1_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)
    stop_ping(hs2)

    print(packets)
    h1_request_1 = False
    h1_request_2 = False
    h1_reply_1 = False
    h1_reply_2 = False
    h2_request_1 = False
    h2_request_2 = False
    h2_reply_1 = False
    h2_reply_2 = False
    print(packets)
    for index, packet in enumerate(packets.split('\n')):
        # Ignore first packet, it is formated bad because of how
        # scapy returns the output
        if index == 0 or "ICMPType" not in packet:
            continue
        data = get_packet_data(packet)
        print(str(data))
        # Dest and src mac addresses and ttl have no meaning for VLAN test
        # Ignore the checks for the VLAN test
        if which_test == 'vlan':
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_request_1 = True
                    h1_request_2 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_request_1 = True
                    h2_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_reply_1 = True
                    h1_reply_2 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_reply_1 = True
                    h2_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h1_request_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs2_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs2_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_request_2 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs2_ip_info['macAddr']
                     and data['ethDst'] == switch_mac_addr
                     and data['ttl'] == str(default_ttl)):
                    h2_request_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h2_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl - 1)):
                    h1_reply_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs2_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs2_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 2)):
                    h1_reply_2 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs2_ip_info['macAddr']
                     and data['ethDst'] == switch_mac_addr
                     and data['ttl'] == str(default_ttl - 1)):
                    h2_reply_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 2)):
                    h2_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h1_request_1, "Didn't get H1 1st Hop ping requests" + packets
    assert h1_request_2, "Didn't get H1 2nd Hop ping requests" + packets
    assert h1_reply_1, "Didn't get H1 2nd Hop ping replies" + packets
    assert h1_reply_2, "Didn't get H1 3rd Hop ping replies" + packets
    assert h2_request_1, "Didn't get H2 1st Hop ping requests" + packets
    assert h2_request_2, "Didn't get H2 2nd Hop ping requests" + packets
    assert h2_reply_1, "Didn't get H2 2nd Hop ping replies" + packets
    assert h2_reply_2, "Didn't get H2 3rd Hop ping replies" + packets
    packets = ""

    # Shutdown other mirror
    shutdown_dual_source_mirror(ops)

    print("##############################################################")
    print("Test case 7 - hs1->hs2 and hs2->hs1, tx mirror on if01 and rx ")
    print("mirror on if02")
    print("##############################################################")
    # Two Source Ports in mirror.
    dual_source_mirror(ops, direction_s1='tx', direction_s2='rx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs1, hs2_ip_info)
    start_ping(hs2, hs1_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)
    stop_ping(hs2)

    print(packets)
    h2_request_1 = False
    h2_request_2 = False
    h2_reply_1 = False
    h2_reply_2 = False
    print(packets)
    for index, packet in enumerate(packets.split('\n')):
        # Ignore first packet, it is formated bad because of how
        # scapy returns the output
        if index == 0 or "ICMPType" not in packet:
            continue
        data = get_packet_data(packet)
        print(str(data))
        # Dest and src mac addresses and ttl have no meaning for VLAN test
        # Ignore the checks for the VLAN test
        if which_test == 'vlan':
            if data['ICMPType'] == 'echo-request':
                if(hs2_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h2_request_1 = True
                    h2_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs2_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h2_reply_1 = True
                    h2_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs2_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs2_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h2_request_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h2_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs2_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs2_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl - 1)):
                    h2_reply_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 2)):
                    h2_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h2_request_1, "Didn't get H2 1st Hop ping requests" + packets
    assert h2_request_2, "Didn't get H2 2nd Hop ping requests" + packets
    assert h2_reply_1, "Didn't get H2 2nd Hop ping replies" + packets
    assert h2_reply_2, "Didn't get H2 3rd Hop ping replies" + packets
    packets = ""

    # Shutdown other mirror
    shutdown_dual_source_mirror(ops)

    print("################################################################")
    print("Test case 8 - hs1->hs2 and hs2->hs1, both mirror on if01 and tx ")
    print("mirror on if02")
    print("################################################################")
    # Two Source Ports in mirror.
    dual_source_mirror(ops, direction_s1='both', direction_s2='tx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs1, hs2_ip_info)
    start_ping(hs2, hs1_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)
    stop_ping(hs2)

    print(packets)
    h1_request_1 = False
    h1_request_2 = False
    h1_reply_1 = False
    h1_reply_2 = False
    h2_request_2 = False
    h2_reply_2 = False
    print(packets)
    for index, packet in enumerate(packets.split('\n')):
        # Ignore first packet, it is formated bad because of how
        # scapy returns the output
        if index == 0 or "ICMPType" not in packet:
            continue
        data = get_packet_data(packet)
        print(str(data))
        # Dest and src mac addresses and ttl have no meaning for VLAN test
        # Ignore the checks for the VLAN test
        if which_test == 'vlan':
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_request_1 = True
                    h1_request_2 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_reply_1 = True
                    h1_reply_2 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h1_request_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs2_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs2_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_request_2 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h2_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl - 1)):
                    h1_reply_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs2_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs2_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 2)):
                    h1_reply_2 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 2)):
                    h2_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h1_request_1, "Didn't get H1 1st Hop ping requests" + packets
    assert h1_request_2, "Didn't get H1 2nd Hop ping requests" + packets
    assert h1_reply_1, "Didn't get H1 2nd Hop ping replies" + packets
    assert h1_reply_2, "Didn't get H1 3rd Hop ping replies" + packets
    assert h2_request_2, "Didn't get H2 2nd Hop ping requests" + packets
    assert h2_reply_2, "Didn't get H2 3rd Hop ping replies" + packets
    packets = ""

    # Shutdown other mirror
    shutdown_dual_source_mirror(ops)

    print("################################################################")
    print("Test case 9 - hs1->hs2 and hs2->hs1, both mirror on if01 and rx ")
    print("mirror on if02")
    print("################################################################")
    # Two Source Ports in mirror.
    dual_source_mirror(ops, direction_s1='both', direction_s2='rx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs1, hs2_ip_info)
    start_ping(hs2, hs1_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)
    stop_ping(hs2)

    print(packets)
    h1_request_1 = False
    h1_reply_1 = False
    h2_request_1 = False
    h2_request_2 = False
    h2_reply_1 = False
    h2_reply_2 = False
    for index, packet in enumerate(packets.split('\n')):
        # Ignore first packet, it is formated bad because of how
        # scapy returns the output
        if index == 0 or "ICMPType" not in packet:
            continue
        data = get_packet_data(packet)
        print(str(data))
        # Dest and src mac addresses and ttl have no meaning for VLAN test
        # Ignore the checks for the VLAN test
        if which_test == 'vlan':
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_request_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_request_1 = True
                    h2_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    h1_reply_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']):
                    h2_reply_1 = True
                    h2_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h1_request_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs2_ip_info['macAddr']
                     and data['ethDst'] == switch_mac_addr
                     and data['ttl'] == str(default_ttl)):
                    h2_request_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h2_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == switch_mac_addr
                   and data['ttl'] == str(default_ttl - 1)):
                    h1_reply_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs2_ip_info['macAddr']
                     and data['ethDst'] == switch_mac_addr
                     and data['ttl'] == str(default_ttl - 1)):
                    h2_reply_1 = True
                elif(hs2_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == switch_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 2)):
                    h2_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h1_request_1, "Didn't get H1 1st Hop ping requests" + packets
    assert h1_reply_1, "Didn't get H1 2nd Hop ping replies" + packets
    assert h2_request_1, "Didn't get H2 1st Hop ping requests" + packets
    assert h2_request_2, "Didn't get H2 2nd Hop ping requests" + packets
    assert h2_reply_1, "Didn't get H2 2nd Hop ping replies" + packets
    assert h2_reply_2, "Didn't get H2 3rd Hop ping replies" + packets
    packets = ""

    # Shutdown other mirror
    shutdown_dual_source_mirror(ops)

    print("############################################")
    print("Test case 10 - No mirrors. expect no traffic")
    print("############################################")
    shutdown_mirror_if01_config(ops)
    shutdown_mirror_if02_config(ops)
    shutdown_dual_source_mirror(ops)
    print("Waiting for 2 secs")
    sleep(2)
    packets = ""

    start_ping(hs1, hs2_ip_info)
    start_ping(hs2, hs1_ip_info)
    packets = sn1.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)
    stop_ping(hs2)
    print("############################################")
    # Dictionaries return false if empty
    assert not get_packet_data(packets), "Recieved packets: " + packets

    # TODO:
    # Test cpu Generated packet, when it is supported. You are able to
    # ping the port but you will never get a ping reply back


def get_packet_data(packet_data):
    parsed_data = {}
    for field in packet_data.split(' '):
        if "=" in field:
            s1 = field.split("=")[0]
            s2 = field.split("=")[1]
            parsed_data[s1] = s2
        else:
            continue
    return parsed_data


def start_ping(hs, other_hs_ip_info):
    hs.send_command('ping -q -i 0.5 -t ' + str(default_ttl) + ' ' +
                    other_hs_ip_info['ip'] + ' > /dev/null &', shell='bash')


def stop_ping(hs):
    hs.send_command('pkill ping', shell='bash')


def mirror_if01_config(ops, direction='both'):
    with ops.libs.vtysh.ConfigMirrorSession('if01_config') as ctx:
        ctx.source_interface('if01', direction)
        ctx.destination_interface('if06')
        ctx.no_shutdown()


def mirror_if02_config(ops, direction='both'):
    with ops.libs.vtysh.ConfigMirrorSession('if02_config') as ctx:
        ctx.source_interface('if02', direction)
        ctx.destination_interface('if06')
        ctx.no_shutdown()


def dual_source_mirror(ops, direction_s1='both', direction_s2='both'):
    with ops.libs.vtysh.ConfigMirrorSession('dual_source_mirror') as ctx:
        ctx.source_interface('if01', direction_s1)
        ctx.source_interface('if02', direction_s2)
        ctx.destination_interface('if06')
        ctx.no_shutdown()


def shutdown_mirror_if01_config(ops):
    with ops.libs.vtysh.ConfigMirrorSession('if01_config') as ctx:
        ctx.shutdown()


def shutdown_mirror_if02_config(ops):
    with ops.libs.vtysh.ConfigMirrorSession('if02_config') as ctx:
        ctx.shutdown()


def shutdown_dual_source_mirror(ops):
    with ops.libs.vtysh.ConfigMirrorSession('dual_source_mirror') as ctx:
        ctx.shutdown()
