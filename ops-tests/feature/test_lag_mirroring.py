
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
OpenSwitch Mirror LAG Traffic
"""

from time import sleep

from pytest import mark

# from pytest import set_trace

TOPOLOGY = """
#                                          +-------+
#                                          |       |
#               +------+    +------+    +--+  hs1  |
#               |      |    |      |    |  |       |
# +-------+     |      +----+      +----+  +-------+
# |       |     |      +----+      |
# |  hs3  +-----+ ops2 |    | ops1 |
# |       |     |      |    |      +----+  +-------+
# +-------+     |      |    |      |    |  |       |
#               |      |    |      |    +--+  hs2  |
#               +------+    +------+       |       |
#                                          +-------+
# Nodes

[type=openswitch name="OpenSwitch 1"] ops1
[type=openswitch name="OpenSwitch 1"] ops2
[type=host name="Host 1"] hs1
[type=host name="Host 2" image="openswitch/ubuntuscapy:latest"] hs2
[type=host name="Host 3" image="openswitch/ubuntuscapy:latest"] hs3

# Links
hs1:if01 -- ops1:if05
hs2:if01 -- ops1:if06
ops1:if01 -- ops2:if01
ops1:if02 -- ops2:if02
hs3:if01 -- ops2:if06
"""

hs1_ip_info = {'ip': '10.10.10.1', 'ip_mask': '10.10.10.1/24',
               'subnet': '10.10.10.0/24'}
hs2_ip_info = {'ip': '10.10.20.1', 'ip_mask': '10.10.20.1/24',
               'subnet': '10.10.20.0/24'}
hs3_ip_info = {'ip': '10.10.30.1', 'ip_mask': '10.10.30.1/24',
               'subnet': '10.10.30.0/24'}

# Switch interfaces connected to hosts
ops1_if05_ip_info = {'ip': '10.10.10.2', 'ip_mask': '10.10.10.2/24',
                     'subnet': '10.10.10.0/24'}
ops1_if06_ip_info = {'ip': '10.10.20.2', 'ip_mask': '10.10.20.2/24',
                     'subnet': '10.10.20.0/24'}

# Switch interfaces connected to the LAG
ops1_lag_info = {'ip': '10.10.30.2', 'ip_mask': '10.10.30.2/24',
                 'subnet': '10.10.30.0/24'}

lag_id = '100'
lag_interface = 'lag' + lag_id
ops1_vlan = '10'
ops2_vlan = '20'
default_ttl = 64

scapy_sniff_command = ""
get_host_mac_command = "ifconfig {} | awk '/HWaddr/ {{print $5}}'"
ops1_mac_addr = ""
which_test = 'vlan'


@mark.timeout(1200)
@mark.platform_incompatible(['docker'])
def test_lag_mirror_routing(topology):
    global which_test
    which_test = 'routing'
    ops1, ops2, hs1, hs2, hs3 = setup_topology(topology)
    run_lag_mirror_test(ops1, ops2, hs1, hs2, hs3)


@mark.timeout(1200)
@mark.platform_incompatible(['docker'])
def test_lag_mirror_vlan(topology):
    global which_test
    which_test = 'vlan'
    ops1, ops2, hs1, hs2, hs3 = setup_topology(topology)
    run_lag_mirror_test(ops1, ops2, hs1, hs2, hs3)


def setup_topology(topology):
    assert topology is not None
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    hs3 = topology.get('hs3')

    global scapy_sniff_command
    scapy_sniff_command = "echo \'sniff(iface=\"{}\"," \
                          "filter=\"icmp\"," \
                          "prn=lambda x:x.sprintf(\"" \
                          "{{ICMP:ICMPType=%ICMP.type% }}" \
                          "{{IP:srcIP=%IP.src% dstIP=%IP.dst% " \
                          "ttl=%IP.ttl% }}{{Ether:ethSrc=%Ether.src% " \
                          "ethDst=%Ether.dst%}}\"), timeout=5)\' | "\
                          "scapy 2>/dev/null".format(hs3.ports['if01'])

    if(which_test == 'vlan'):
        # Change global that is used for routing and vlan test. Need to make
        # hs2 and hs3 on same subnet as hs1 for this test. By default they
        # are set to be on seperate subnets
        # (routing test requires different subnets)
        hs2_ip_info['ip'] = '10.10.10.2'
        hs2_ip_info['ip_mask'] = '10.10.10.2/24'
        hs3_ip_info['ip'] = '10.10.10.3'
        hs3_ip_info['ip_mask'] = '10.10.10.3/24'

    # Configure IP and bring UP host 1 interfaces
    hs1.libs.ip.interface('if01', addr=hs1_ip_info['ip_mask'], up=True)

    # Configure IP and bring UP host 2 interfaces
    hs2.libs.ip.interface('if01', addr=hs2_ip_info['ip_mask'], up=True)

    # Configure IP and bring UP sniffer 3 interfaces
    ifg = "ifconfig {} promisc".format(hs3.ports['if01'])
    hs3.send_command(ifg, shell='bash')
    hs3.libs.ip.interface('if01', addr=hs3_ip_info['ip_mask'], up=True)

    if(which_test == 'routing'):
        configure_lag_routes(ops1, ops2, hs1, hs2, hs3)
    elif(which_test == 'vlan'):
        configure_lag_vlan(ops1, ops2, hs1, hs2, hs3)
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
    hs3_ip_info['macAddr'] = hs3.send_command(
                                get_host_mac_command.format(hs3.ports['if01']),
                                shell='bash')
    # All interfaces should have the same MAC address
    global ops1_mac_addr
    ops1_mac_addr = ops1.libs.vtysh.show_interface('if01')['mac_address']
    print("Switch1 MAC addr " + ops1_mac_addr)
    return ops1, ops2, hs1, hs2, hs3


def run_lag_mirror_test(ops1, ops2, hs1, hs2, hs3):
    # Disclaimer:
    # Dest and src mac addresses and TTl have no meaning for VLAN test
    # they are only valid for Routing test.

    global which_test
    print("#########################################")
    print("Test case 1 - hs3->hs1, rx mirror on LAG ")
    print("LAG is source interface")
    print("#########################################")
    # Setup mirror
    lag_source_mirror(ops1, lag_interface, 'if06', direction='rx')

    # Only expect request packets from hs1
    start_ping(hs3, hs1_ip_info)
    packets = hs2.send_command(scapy_sniff_command, shell='bash')

    stop_ping(hs3)
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
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    passed = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    passed = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet

    assert passed, "didn't receive expected packet "
    packets = ""

    # Shutdown Other Mirror
    remove_lag_source_mirror(ops1)
    print("Waiting for 2 secs")
    sleep(2)

    print("##########################################")
    print("Test case 2 - hs3->hs1, tx mirror on LAG ")
    print("LAG is source interface")
    print("##########################################")
    # Setup mirror
    lag_source_mirror(ops1, lag_interface, 'if06', direction='tx')
    print("Waiting for 2 secs")
    sleep(2)

    # Testing Tx, only expect reply packets from hs2
    start_ping(hs3, hs1_ip_info)
    packets = hs2.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs3)
    print(packets)
    h1_reply = False
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
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs3_ip_info['ip'] == data['dstIP']):
                    h1_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs3_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == ops1_mac_addr
                   and data['ethDst'] == hs3_ip_info['macAddr']
                   and data['ttl'] == str(default_ttl - 1)):
                    h1_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet

    assert h1_reply, "didn't get Host 1 ping reply packets" + packets
    packets = ""

    # ShutDown other mirror
    remove_lag_source_mirror(ops1)
    print("Waiting for 2 secs")
    sleep(2)

    print("###########################################")
    print("Test case 3 - hs3->hs1, both mirror on LAG ")
    print("LAG is source interface")
    print("###########################################")
    # Setup mirror
    lag_source_mirror(ops1, lag_interface, 'if06', direction='both')
    print("Waiting for 2 secs")
    sleep(2)

    # Testing 'both' so expect requests from h1 and replies from h2
    start_ping(hs3, hs1_ip_info)
    packets = hs2.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs3)

    h3_request = False
    h1_reply = False
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
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs3_ip_info['ip'] == data['dstIP']):
                    h1_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h3_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs3_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == ops1_mac_addr
                   and data['ethDst'] == hs3_ip_info['macAddr']
                   and data['ttl'] == str(default_ttl - 1)):
                    h1_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet

    assert h3_request, "didn't get Host 3 ping request packets" + packets
    assert h1_reply, "didn't get Host 1 ping reply packets" + packets
    packets = ""

    # Shutdown Other Mirror
    remove_lag_source_mirror(ops1)
    print("Waiting for 2 secs")
    sleep(2)

    print("##############################################################")
    print("Test case 4- hs1->hs3 and hs3->hs1, rx mirror on if05 and LAG ")
    print("##############################################################")
    # Two Source Ports in mirror. Expect Ping Requests from both hosts
    dual_source_mirror(ops1, src_int_1=lag_interface, src_int_2='if05',
                       dest_int='if06', direction_s1='rx', direction_s2='rx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs3, hs1_ip_info)
    start_ping(hs1, hs3_ip_info)
    packets = hs2.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs3)
    stop_ping(hs1)

    print(packets)
    h3_request = False
    h3_reply = False
    h1_request = False
    h1_reply = False
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
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_request = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_reply = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h3_request = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs1_ip_info['macAddr']
                     and data['ethDst'] == ops1_mac_addr
                     and data['ttl'] == str(default_ttl)):
                    h1_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h3_reply = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs1_ip_info['macAddr']
                     and data['ethDst'] == ops1_mac_addr
                     and data['ttl'] == str(default_ttl)):
                    h1_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet

    assert h3_request, "didn't get Host 3 ping request packets" + packets
    assert h1_request, "didn't get Host 1 ping request packets" + packets
    assert h3_reply, "didn't get Host 3 ping reply packets" + packets
    assert h1_reply, "didn't get Host 1 ping reply packets" + packets
    packets = ""

    # Shutdown Other Mirror
    remove_dual_source_mirror(ops1)
    print("Waiting for 2 secs")
    sleep(2)

    print("###############################################################")
    print("Test case 5- hs3->hs1 and hs3->hs1, tx mirror on if05 and LAG ")
    print("###############################################################")
    # Two Source Ports in mirror.
    dual_source_mirror(ops1, src_int_1=lag_interface, src_int_2='if05',
                       dest_int='if06', direction_s1='tx', direction_s2='tx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs3, hs1_ip_info)
    start_ping(hs1, hs3_ip_info)
    packets = hs2.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs3)
    stop_ping(hs1)

    h3_request = False
    h3_reply = False
    h1_request = False
    h1_reply = False
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
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_request = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_reply = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == ops1_mac_addr
                   and data['ethDst'] == hs1_ip_info['macAddr']
                   and data['ttl'] == str(default_ttl - 1)):
                    h3_request = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_request = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == ops1_mac_addr
                   and data['ethDst'] == hs1_ip_info['macAddr']
                   and data['ttl'] == str(default_ttl - 1)):
                    h3_reply = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_reply = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h3_request, "didn't get Host 3 ping request packets" + packets
    assert h1_request, "didn't get Host 1 ping request packets" + packets
    assert h3_reply, "didn't get Host 3 ping reply packets" + packets
    assert h1_reply, "didn't get Host 1 ping reply packets" + packets
    packets = ""

    # Shutdown Other Mirror
    remove_dual_source_mirror(ops1)
    print("Waiting for 2 secs")
    sleep(2)

    print("################################################################")
    print("Test case 6- hs3->hs1 and hs3->hs1, both mirror on if05 and LAG ")
    print("################################################################")
    # Two Source Ports in mirror.
    dual_source_mirror(ops1, src_int_1=lag_interface, src_int_2='if05',
                       dest_int='if06',
                       direction_s1='both',
                       direction_s2='both')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs3, hs1_ip_info)
    start_ping(hs1, hs3_ip_info)
    packets = hs2.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs3)
    stop_ping(hs1)

    print(packets)
    h3_request_1 = False
    h3_request_2 = False
    h3_reply_1 = False
    h3_reply_2 = False
    h1_request_1 = False
    h1_request_2 = False
    h1_reply_1 = False
    h1_reply_2 = False
    print_mac_addrs()
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
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_request_1 = True
                    h3_request_2 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_request_1 = True
                    h1_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_reply_1 = True
                    h3_reply_2 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_reply_1 = True
                    h1_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h3_request_1 = True
                elif(hs3_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h3_request_2 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs1_ip_info['macAddr']
                     and data['ethDst'] == ops1_mac_addr
                     and data['ttl'] == str(default_ttl)):
                    h1_request_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h3_reply_1 = True
                elif(hs3_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h3_reply_2 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs1_ip_info['macAddr']
                     and data['ethDst'] == ops1_mac_addr
                     and data['ttl'] == str(default_ttl)):
                    h1_reply_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h3_request_1, "Didn't get H1 1st Hop ping requests" + packets
    assert h3_request_2, "Didn't get H1 2nd Hop ping requests" + packets
    assert h3_reply_1, "Didn't get H1 2nd Hop ping replies" + packets
    assert h3_reply_2, "Didn't get H1 3rd Hop ping replies" + packets
    assert h1_request_1, "Didn't get H2 1st Hop ping requests" + packets
    assert h1_request_2, "Didn't get H2 2nd Hop ping requests" + packets
    assert h1_reply_1, "Didn't get H2 2nd Hop ping replies" + packets
    assert h1_reply_2, "Didn't get H2 3rd Hop ping replies" + packets
    packets = ""

    remove_dual_source_mirror(ops1)
    print("Waiting for 2 secs")
    sleep(2)

    print("##############################################################")
    print("Test case 7- hs3->hs1 and hs3->hs1, tx mirror on LAG and rx ")
    print("on if05 ")
    print("##############################################################")
    # Two Source Ports in mirror.
    dual_source_mirror(ops1, src_int_1=lag_interface, src_int_2='if05',
                       dest_int='if06',
                       direction_s1='tx',
                       direction_s2='rx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs3, hs1_ip_info)
    start_ping(hs1, hs3_ip_info)
    packets = hs2.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs3)
    stop_ping(hs1)

    print(packets)
    h1_request_1 = False
    h1_request_2 = False
    h1_reply_1 = False
    h1_reply_2 = False
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
                   and hs3_ip_info['ip'] == data['dstIP']):
                    h1_request_1 = True
                    h1_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs3_ip_info['ip'] == data['dstIP']):
                    h1_reply_1 = True
                    h1_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs3_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h1_request_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs3_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h1_reply_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h1_request_1, "Didn't get H2 1st Hop ping requests" + packets
    assert h1_request_2, "Didn't get H2 2nd Hop ping requests" + packets
    assert h1_reply_1, "Didn't get H2 2nd Hop ping replies" + packets
    assert h1_reply_2, "Didn't get H2 3rd Hop ping replies" + packets
    packets = ""

    # Shut down other mirror
    remove_dual_source_mirror(ops1)
    print("Waiting for 2 secs")
    sleep(2)

    print("###############################################################")
    print("Test case 8 - hs1->hs2 and hs2->hs1, both mirror on LAG and tx ")
    print("mirror on if05")
    print("###############################################################")
    # Two Source Ports in mirror.
    dual_source_mirror(ops1, src_int_1=lag_interface, src_int_2='if05',
                       dest_int='if06',
                       direction_s1='both',
                       direction_s2='tx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs3, hs1_ip_info)
    start_ping(hs1, hs3_ip_info)
    packets = hs2.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs3)
    stop_ping(hs1)

    print(packets)
    h3_request_1 = False
    h3_request_2 = False
    h3_reply_1 = False
    h3_reply_2 = False
    h1_request_2 = False
    h1_reply_2 = False
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
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_request_1 = True
                    h3_request_2 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_reply_1 = True
                    h3_reply_2 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h3_request_1 = True
                elif(hs3_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h3_request_2 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h3_reply_1 = True
                elif(hs3_ip_info['ip'] == data['srcIP']
                     and hs1_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs1_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h3_reply_2 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h3_request_1, "Didn't get H1 1st Hop ping requests" + packets
    assert h3_request_2, "Didn't get H1 2nd Hop ping requests" + packets
    assert h3_reply_1, "Didn't get H1 2nd Hop ping replies" + packets
    assert h3_reply_2, "Didn't get H1 3rd Hop ping replies" + packets
    assert h1_request_2, "Didn't get H2 2nd Hop ping requests" + packets
    assert h1_reply_2, "Didn't get H2 3rd Hop ping replies" + packets
    packets = ""

    # Shutdown other mirror
    remove_dual_source_mirror(ops1)
    print("Waiting for 2 secs")
    sleep(2)

    print("################################################################")
    print("Test case 9 - hs1->hs2 and hs2->hs1, both mirror on LAG and rx ")
    print("mirror on if05")
    print("################################################################")

    # Two Source Ports in mirror.
    dual_source_mirror(ops1, src_int_1=lag_interface, src_int_2='if05',
                       dest_int='if06',
                       direction_s1='both',
                       direction_s2='rx')
    print("Waiting for 2 secs")
    sleep(2)

    start_ping(hs3, hs1_ip_info)
    start_ping(hs1, hs3_ip_info)
    packets = hs2.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs3)
    stop_ping(hs1)

    print(packets)
    h3_request_1 = False
    h3_reply_1 = False
    h1_request_1 = False
    h1_request_2 = False
    h1_reply_1 = False
    h1_reply_2 = False
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
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_request_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_request_1 = True
                    h1_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']):
                    h3_reply_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']):
                    h1_reply_1 = True
                    h1_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h3_request_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs1_ip_info['macAddr']
                     and data['ethDst'] == ops1_mac_addr
                     and data['ttl'] == str(default_ttl)):
                    h1_request_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_request_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            elif data['ICMPType'] == 'echo-reply':
                if(hs3_ip_info['ip'] == data['srcIP']
                   and hs1_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs3_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    h3_reply_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == hs1_ip_info['macAddr']
                     and data['ethDst'] == ops1_mac_addr
                     and data['ttl'] == str(default_ttl)):
                    h1_reply_1 = True
                elif(hs1_ip_info['ip'] == data['srcIP']
                     and hs3_ip_info['ip'] == data['dstIP']
                     and data['ethSrc'] == ops1_mac_addr
                     and data['ethDst'] == hs3_ip_info['macAddr']
                     and data['ttl'] == str(default_ttl - 1)):
                    h1_reply_2 = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
    assert h3_request_1, "Didn't get H1 1st Hop ping requests" + packets
    assert h3_reply_1, "Didn't get H1 2nd Hop ping replies" + packets
    assert h1_request_1, "Didn't get H2 1st Hop ping requests" + packets
    assert h1_request_2, "Didn't get H2 2nd Hop ping requests" + packets
    assert h1_reply_1, "Didn't get H2 2nd Hop ping replies" + packets
    assert h1_reply_2, "Didn't get H2 3rd Hop ping replies" + packets
    packets = ""

    # Configure ops1 if06 to send traffic
    if(which_test == 'routing'):
        config_ops1_if06_ip_addr(ops1)
    elif(which_test == 'vlan'):
        config_ops1_if06_vlan(ops1)
    # Shutdown other Mirror
    remove_dual_source_mirror(ops1)
    print("Waiting for 2 secs")
    sleep(2)

    print("###########################################")
    print("Test case 10 - hs1->hs2, rx mirror on if05 ")
    print("LAG as destination Interface")
    print("###########################################")
    # Setup mirror
    lag_dest_mirror(ops1, lag_interface, 'if05', direction='rx')
    # Need to add a mirror to ops2 to see if the LAG from ops1
    # actually was the destination interface for the mirror
    lag_source_mirror(ops2, lag_interface, 'if06', direction='both')

    # Only expect request packets from hs1
    start_ping(hs1, hs2_ip_info)
    packets = hs3.send_command(scapy_sniff_command, shell='bash')

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
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']):
                    passed = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet
        else:
            if data['ICMPType'] == 'echo-request':
                if(hs1_ip_info['ip'] == data['srcIP']
                   and hs2_ip_info['ip'] == data['dstIP']
                   and data['ethSrc'] == hs1_ip_info['macAddr']
                   and data['ethDst'] == ops1_mac_addr
                   and data['ttl'] == str(default_ttl)):
                    passed = True
                else:
                    assert False, "Bad Packet : " + packet
            else:
                assert False, "Bad Packet : " + packet

    assert passed, "didn't receive expected packet "
    packets = ""

    print("############################################")
    print("Test case 11 - No mirrors. expect no traffic")
    print("############################################")
    # Shutdown other mirror
    remove_lag_dest_mirror(ops1)
    remove_lag_source_mirror(ops2)
    print("Waiting for 2 secs")
    sleep(2)
    packets = ""

    start_ping(hs1, hs2_ip_info)
    start_ping(hs2, hs1_ip_info)
    packets = hs3.send_command(scapy_sniff_command, shell='bash')
    stop_ping(hs1)
    stop_ping(hs2)
    print("############################################")
    # Dictionaries return false if empty
    assert not get_packet_data(packets), "Recieved packets: " + packets


def configure_lag_routes(ops1, ops2, hs1, hs2, hs3):
    ##################
    # Setup SW1
    ##################
    # Setup lag
    with ops1.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.no_shutdown()
        ctx.ip_address(ops1_lag_info['ip_mask'])

    # Configure ops1 LAG interfaces
    with ops1.libs.vtysh.ConfigInterface('if01') as ctx:
        ctx.lag(lag_id)
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('if02') as ctx:
        ctx.lag(lag_id)
        ctx.no_shutdown()

    # Configure IP and bring UP switch 1 interfaces
    with ops1.libs.vtysh.ConfigInterface('if05') as ctx:
        ctx.ip_address(ops1_if05_ip_info['ip_mask'])
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('if06') as ctx:
        ctx.no_shutdown()

    ##################
    # Setup SW2
    ##################
    # Setup Vlan
    with ops2.libs.vtysh.ConfigVlan(ops2_vlan) as ctx:
        ctx.no_shutdown()
    # Setup ops2 LAG
    with ops2.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.no_routing()
        ctx.vlan_access(ops2_vlan)
        ctx.no_shutdown()

    # Configure ops2 LAG interfaces
    with ops2.libs.vtysh.ConfigInterface('if01') as ctx:
        ctx.lag(lag_id)
        ctx.no_shutdown()

    with ops2.libs.vtysh.ConfigInterface('if02') as ctx:
        ctx.lag(lag_id)
        ctx.no_shutdown()

    # Configure IP and bring UP switch 2 interfaces
    with ops2.libs.vtysh.ConfigInterface('if06') as ctx:
        ctx.no_routing()
        ctx.vlan_access(ops2_vlan)
        ctx.no_shutdown()

    add_route_string = "ip -4 route add {dest} via {gw} dev {device}"
    hs1.send_command(add_route_string.format(dest=hs2_ip_info['subnet'],
                                             gw=ops1_if05_ip_info['ip'],
                                             device=hs1.ports['if01']))
    hs1.send_command(add_route_string.format(dest=hs3_ip_info['subnet'],
                                             gw=ops1_if05_ip_info['ip'],
                                             device=hs1.ports['if01']))
    hs2.send_command(add_route_string.format(dest=hs1_ip_info['subnet'],
                                             gw=ops1_if06_ip_info['ip'],
                                             device=hs2.ports['if01']))
    hs2.send_command(add_route_string.format(dest=hs3_ip_info['subnet'],
                                             gw=ops1_if06_ip_info['ip'],
                                             device=hs2.ports['if01']))
    hs3.send_command(add_route_string.format(dest=hs1_ip_info['subnet'],
                                             gw=ops1_lag_info['ip'],
                                             device=hs3.ports['if01']))
    hs3.send_command(add_route_string.format(dest=hs2_ip_info['subnet'],
                                             gw=ops1_lag_info['ip'],
                                             device=hs3.ports['if01']))


def configure_lag_vlan(ops1, ops2, hs1, hs2, hs3):
    ##################
    # Setup SW1
    ##################
    # Setup Vlan
    with ops1.libs.vtysh.ConfigVlan(ops2_vlan) as ctx:
        ctx.no_shutdown()
    # Setup lag
    with ops1.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.no_shutdown()
        ctx.no_routing()
        ctx.vlan_access(ops2_vlan)

    # Configure ops1 LAG interfaces
    with ops1.libs.vtysh.ConfigInterface('if01') as ctx:
        ctx.lag(lag_id)
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('if02') as ctx:
        ctx.lag(lag_id)
        ctx.no_shutdown()

    # Configure IP and bring UP switch 1 interfaces
    with ops1.libs.vtysh.ConfigInterface('if05') as ctx:
        ctx.no_routing()
        ctx.vlan_access(ops2_vlan)
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('if06') as ctx:
        ctx.no_shutdown()

    ##################
    # Setup SW2
    ##################
    # Setup Vlan
    with ops2.libs.vtysh.ConfigVlan(ops2_vlan) as ctx:
        ctx.no_shutdown()
    # Setup ops2 LAG
    with ops2.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.no_routing()
        ctx.vlan_access(ops2_vlan)
        ctx.no_shutdown()

    # Configure ops2 LAG interfaces
    with ops2.libs.vtysh.ConfigInterface('if01') as ctx:
        ctx.lag(lag_id)
        ctx.no_shutdown()

    with ops2.libs.vtysh.ConfigInterface('if02') as ctx:
        ctx.lag(lag_id)
        ctx.no_shutdown()

    # Configure IP and bring UP switch 2 interfaces
    with ops2.libs.vtysh.ConfigInterface('if06') as ctx:
        ctx.no_routing()
        ctx.vlan_access(ops2_vlan)
        ctx.no_shutdown()


def config_ops1_if06_ip_addr(ops1):
    with ops1.libs.vtysh.ConfigInterface('if06') as ctx:
        ctx.ip_address(ops1_if06_ip_info['ip_mask'])
        ctx.no_shutdown()


def config_ops1_if06_vlan(ops1):
    with ops1.libs.vtysh.ConfigInterface('if06') as ctx:
        ctx.no_shutdown()
        ctx.no_routing()
        ctx.vlan_access(ops2_vlan)


def start_ping(hs, other_hs_ip_info):
    hs.send_command('ping -q -i 0.2 ' + other_hs_ip_info['ip'] +
                    ' > /dev/null &', shell='bash')


def stop_ping(hs):
    hs.send_command('pkill ping', shell='bash')


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


def lag_source_mirror(ops, lag_interface, dest_interface, direction='both'):
    with ops.libs.vtysh.ConfigMirrorSession('lag_source_mirror') as ctx:
        ctx.source_interface(lag_interface, direction)
        ctx.destination_interface(dest_interface)
        ctx.no_shutdown()


def remove_lag_source_mirror(ops):
    with ops.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session('lag_source_mirror')


def lag_dest_mirror(ops, lag_interface, src_interface, direction='both'):
    with ops.libs.vtysh.ConfigMirrorSession('lag_dest_mirror') as ctx:
        ctx.source_interface(src_interface, direction)
        ctx.destination_interface(lag_interface)
        ctx.no_shutdown()


def remove_lag_dest_mirror(ops):
    with ops.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session('lag_dest_mirror')


def dual_source_mirror(ops, src_int_1, src_int_2, dest_int,
                       direction_s1='both', direction_s2='both'):
    with ops.libs.vtysh.ConfigMirrorSession('dual_source_mirror') as ctx:
        ctx.source_interface(src_int_1, direction_s1)
        ctx.source_interface(src_int_2, direction_s2)
        ctx.destination_interface(dest_int)
        ctx.no_shutdown()


def remove_dual_source_mirror(ops):
    with ops.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session('dual_source_mirror')


def print_mac_addrs():
    print("hs1: " + hs1_ip_info['macAddr'])
    print("hs2: " + hs2_ip_info['macAddr'])
    print("hs3: " + hs3_ip_info['macAddr'])
    print("sw1: " + ops1_mac_addr)
