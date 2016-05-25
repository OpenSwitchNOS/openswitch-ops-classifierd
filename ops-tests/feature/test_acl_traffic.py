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
OpenSwitch Test for ACL on Port related configurations.
"""

from pytest import mark
from re import search
from ipdb import set_trace
from .helpers import wait_until_interface_up
import sys
import threading
from topology_lib_scapy.library import ScapyThread
# from time import sleep, ctime

TOPOLOGY = """
# +-------+                    +-------+
# |       |     +--------+     |       |
# |  hs1  <----->  ops1  <----->  hs2  |
# |       |     +--------+     |       |
# +-------+                    +-------+

# Nodes
# [type=openswitch name="OpenSwitch 1"] ops1
# [type=host name="Host 1"] hs1
# [type=host name="Host 2"] hs2
# #[image="fs-genericx86-64:latest" \
# #type=openswitch name="OpenSwitch 1"] ops1
# #[type=host name="Host 1" image="openswitch/ubuntuscapy:latest"] hs1
# #[type=host name="Host 2" image="openswitch/ubuntuscapy:latest"] hs2
[type=openswitch name="Switch 1"] ops1
[type=host name="Host 1" image="Ubuntu"] hs1
[type=host name="Host 2" image="Ubuntu"] hs2

# Links
hs1:1 -- ops1:1
ops1:2 --hs2:1
"""

global eth


def sendscapypacket(enode, proto_str, list, topology):
    node = topology.get(enode)
    node.libs.scapy.send(proto_str, list)
    print('Send the packet')
    return None


def sniffscapypacket(enode, proto_str, list, topology):
    node = topology.get(enode)
    eth = node.ports['1']
    recdpacket = node.libs.scapy.sniff2(
                            'iface="' + eth + '", '
                            'prn=lambda x: x.summary(), timeout=5'
                                        )
    return recdpacket

functions = [sendscapypacket, sniffscapypacket]


@mark.test_id(10404)
def test_traffic_on_port(topology, step):
    """
    Test the application of IPv4 ACL on a OpenSwitch switch Port.

    Build a topology of one switche and two hosts on the same subnet.
    Tested the ability to apply ACL on switch Port with switched traffic.
    """
    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    p2 = ops1.ports['2']
    p1 = ops1.ports['1']

    # Mark interfaces as enabled
    assert not ops1(
        'set interface {p1} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p2} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )

    # Configure interfaces
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    # FIXME: Use library
    ops1('show interface {p1}'.format(**locals()))
    ops1('show interface {p2}'.format(**locals()))

    # FIXME: Use library
    # Add assertion for show interfaces
    # On actual hardware, 'RTNETLINK answers: File exists' workaround
    # hs1.libs.ip.interface('1', addr='10.0.0.1/24', up=True)
    # hs2.libs.ip.interface('1', addr='10.0.0.2/24', up=True)
    # Configure host interfaces
    hs1.libs.ip.interface('1', addr='10.0.10.1/24', up=True)
    hs2.libs.ip.interface('1', addr='10.0.10.2/24', up=True)

    # VM add vlan and switch interfaces
    # step('Set gateway for hosts')
    # ops1.libs.ip.add_route('default', '10.10.10.1')

    with ops1.libs.vtysh.ConfigVlan('100') as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.vlan_access(100)

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.vlan_access(100)

    # sleep(60)

    step('Wait until interfaces are up')
    for portlbl in ['1', '2']:
        wait_until_interface_up(ops1, portlbl)

    # sleep(60)

    step('################ Apply IPv4 acl on one Port ###############')
    step('################### with switched traffic #################')

    # Configure create an acl on switch with valid name.
    # Run following commands
    # root# config terminal
    # root(config)# access-list ip test1

    # The acl must be present in switch configuration.
    # Run following commands
    # root(config)# exit
    # root# show run
    # test1_result = ops1('show run')

    # Configure acl to add an **acl entry** with valid parameter.
    # Run following commands
    # root# config terminal
    # root(config)# access-list ip test1
    # root(config-acl)# 10 deny tcp any any
    # root(config-acl)# exit
    # root# show run
    # test1_result = ops1('show run')
    # Add assertion for results checking

    step('################ T1 Apply Permit ACL ###########')
    step('################ to interface ###############')
    step('################ A.B.C.D Host  ###############')
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.permit('', '1', 'icmp', '10.0.10.1', '', '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+icmp\s+10\.[0-9]\.10\.1'
       '\s+10\.[0-9]\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    # Configure hs1 to generate traffic
    # hs2 sniff and analyze traffic
    set_trace()

    step('Start scapy on host workstations')
    hs1.libs.scapy.start_scapy()
    hs2.libs.scapy.start_scapy()

    # Apply ACL on port
    # root# config terminal
    # root(config) # interface 7
    # root(config-if)# apply access-list ip test1 in
    # root(config-if)# exit
    # root# show run
    # test1_result = ops1('show run')
    # Add assertion for results checking

    # VM
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test1')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test1\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )
    # VM

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'

    numfuncs = range(len(functions))

    txthread = ScapyThread(
                functions[0],
                'hs1', topology, proto_str, list1, functions[0].__name__)
    rxthread = ScapyThread(
                functions[1],
                'hs2', topology, '', [], functions[1].__name__)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()
    print(rxthread.outresult())

    set_trace()
    if rxthread.outresult():
        assert search(
                ''
                r'ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2\s+'
                'echo-request'.format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.no('1')

    sys.exit(0)


    step('################ T2 Apply Deny ACL ###########')
    step('################ to interface ###############')
    step('################ A.B.C.D Host  ###############')
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.deny('', '1', 'icmp', '10.0.10.1', '', '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+icmp\s+10\.[0-9]\.10\.1'
       '\s+10\.[0-9]\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    # Configure hs1 to generate traffic
    # hs2 sniff and analyze traffic
    set_trace()

    step('Start scapy on host workstations')
    hs1.libs.scapy.start_scapy()
    hs2.libs.scapy.start_scapy()

    # VM
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test2')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test2\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )
    # VM

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'

    numfuncs = range(len(functions))

    txthread = ScapyThread(
                functions[0],
                'hs1', topology, proto_str, list1, functions[0].__name__)
    rxthread = ScapyThread(
                functions[1],
                'hs2', topology, '', [], functions[1].__name__)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()
    print(rxthread.outresult())

    set_trace()
    if rxthread.outresult():
        assert search(
                ''
                r'ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2\s+'
                'echo-request'.format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.no('1')

    sys.exit(0)






    step('################ T2 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ A.B.C.D/M Network  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test2') as ctx:
        ctx.permit('', '2', 'icmp', '10.0.10.1/8', '', '10.0.10.2/8', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'2\s+permit\s+icmp\s+10\.[0-9]\.10\.1/255\.0\.0\.0'
       '\s+10\.[0-9]\.10\.2/255\.255\.255\.0'.format(
                                         **locals()
                                       ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    # sendscapyobj = SendScapy('hs1', list1, topology)
    rxscapyobj = RxScapyT2('hs2', topology)

    try:
        rxscapyobj.start()
        # sleep(5)
        # sendscapyobj.start()

    # raw_input("")
        # sendscapyobj.join()
        rxscapyobj.join()

    except BaseException:
        set_trace()
        print('Rxd error in main thread')
        sys.exit()
    else:
        print('In Main Thread, received Else')
        # sys.exit()

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test2') as ctx:
        ctx.no('2')

    step('################ T8 Apply IPV4 ACL ###########')
    step('################ to interface ###############')
    step('################ proto any Host  ###############')

    step('################ T4b Apply ACL ###########')
    step('################ to interface ###############')
    step('################ igmp protocol  ###############')
    step('################ on one port with   ###############')
    step('################ A.B.C.D/W.X.Y.Z addresses   ###############')

    step('################ T8 Apply IPV4 ACL ###########')
    step('################ to interface ###############')
    step('################ proto any Host  ###############')

    step('################ TX Verify IPV4 ACL ###########')
    step('################ on one port  with any #############')
    step('################ src destn IP addresses ###############')
    step('################ Verify IPV6 blocked  ###############')
    step('################ Verify non IP (ARP) allowed  ###############')

    step('################ T9 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp eq L4  ###############')

    step('################ T10 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp neq L4  ###############')

    step('Exit Scapy')
    # hs1.libs.scapy.exit_scapy()
    # hs2.libs.scapy.exit_scapy()

    # Configure hs1 to generate traffic
    # hs2 sniff and analyze traffic

    # root# config terminal
    # root(config)# interface 7
    # root(config-if)# no apply access-list ip test1 in
    # root(config-if)# exit
    # root# show run
    # test1_result = ops1('show run')
    # Add assertion for results checking

    # Configure hs1 to generate traffic
    # hs2 sniff and analyze traffic

    # Test pass criteria
    # Verify traffic flows before ACL in Port, traffic denied with ACL in Port,
    # confirm traffic flows again when ACL removed.
    # Test fail criteria

    sys.exit(0)
