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
from re import findall
from .helpers import wait_until_interface_up
from topology_lib_scapy.library import ScapyThread

TOPOLOGY = """
# +-------+                    +-------+
# |       |     +--------+     |       |
# |  hs1  <----->  ops1  <----->  hs2  |
# |       |     +--------+     |       |
# +-------+                    +-------+

# Nodes
[type=openswitch name="Switch 1"] ops1
[type=host name="Host 1" image="Ubuntu"] hs1
[type=host name="Host 2" image="Ubuntu"] hs2

# Links
hs1:1 -- ops1:1
ops1:2 -- hs2:1
"""


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
def test_acl_traffic_all_protocols(topology, step):
    """
    Test traffic of various protocols after applying ACEs to ports.

    Build a topology of one switch and two hosts on the same subnet.
    """
    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    p1 = ops1.ports['1']
    p2 = ops1.ports['2']

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

    ops1('show interface {p1}'.format(**locals()))
    ops1('show interface {p2}'.format(**locals()))

    hs1.libs.ip.interface('1', addr='10.0.10.1/24', up=True)
    hs2.libs.ip.interface('1', addr='10.0.10.2/24', up=True)

    with ops1.libs.vtysh.ConfigVlan('100') as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.vlan_access(100)

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.vlan_access(100)

    step('Wait until interfaces are up')
    for portlbl in ['1', '2']:
        wait_until_interface_up(ops1, portlbl)

    step('Start scapy on host workstations')
    hs1.libs.scapy.start_scapy()
    hs2.libs.scapy.start_scapy()

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

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test1')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test1\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

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

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test1')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test1\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T2 Apply Deny ACL ###########')
    step('################ to interface 1 ###############')
    step('################ A.B.C.D Host  ###############')
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test2') as ctx:
        ctx.deny('', '2', 'icmp', '10.0.10.1', '', '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'2\s+deny\s+icmp\s+10\.[0-9]\.10\.1'
       '\s+10\.[0-9]\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test2')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test2\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

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

    if rxthread.outresult():
        assert search(
                ''
                r'(?!ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2)'.format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test2') as ctx:
        ctx.no('2')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test2')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test2\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T3 Apply Deny ACL ###########')
    step('################ to interface 2 ###############')
    step('################ A.B.C.D Host  ###############')
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test3') as ctx:
        ctx.deny('', '3', 'icmp', '10.0.10.1', '', '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'3\s+deny\s+icmp\s+10\.[0-9]\.10\.1'
       '\s+10\.[0-9]\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.apply_access_list_ip_in('test3')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test3\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

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

    if rxthread.outresult():
        assert search(
                ''
                r'(ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2)'
                '\s+echo-request'.format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test3') as ctx:
        ctx.no('3')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test3')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test3\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T4 Apply deny ACL ###########')
    step('################ to interface 1 ###############')
    step('################ any any any ###############')
    step('################ A.B.C.D Host  ###############')
    step('################ Ether / ARP pass  ###############')
    step('################ Ether / IP pass  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.deny('', '4', 'any', 'any', '', 'any', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'4\s+deny\s+any\s+any'
       '\s+any'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test4\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

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

    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)
        assert sum(int(i) for i in list_result[:3]) == 0

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('4')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test4')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test4\s+)'.format(
                                         **locals()
                                     ), test1_result
    )
