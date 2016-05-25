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
from ipdb import set_trace
from .helpers import wait_until_interface_up
from topology_lib_scapy.library import ScapyThread
from topology_lib_scapy.library import ScapyMultiCountThread
# import time

TOPOLOGY = """
# +-------+                    +-------+
# |       |     +--------+     |       |
# |  hs1  <----->  ops1  <----->  hs2  |
# |       |     +--------+     |       |
# +-------+                    +-------+

# Nodes
# [image="fs-genericx86-64:latest" \
# type=openswitch name="OpenSwitch 1"] ops1
# [type=host name="Host 1" image="openswitch/ubuntuscapy:latest"] hs1
# [type=host name="Host 2" image="openswitch/ubuntuscapy:latest"] hs2
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


def sendscapyl2packet(enode, proto_str, list, topology):
    node = topology.get(enode)
    node.libs.scapy.sendp(proto_str, list)
    print('Send the packet')
    return None


def sendsrpacket(enode, proto_str, list, topology):
    node = topology.get(enode)
    node.libs.scapy.srp(proto_str, list)
    print('Send the packet')
    return None


def filterscapypacket(enode, proto_str, list, topology):
    node = topology.get(enode)
    eth = node.ports['1']
    recdpacket = node.libs.scapy.sniff2(
                            'iface="' + eth + '", filter="icmp", '
                            'prn=lambda x: x.summary(), timeout=5'
                                        )
    return recdpacket


def sendsr1packet(enode, proto_str, list, topology):
    node = topology.get(enode)
    # set_trace()
    node.libs.scapy.sr1(proto_str, list)
    print('Send the packet')
    return None


def sendpcountpacket(enode, proto_str, list, topology, count):
    node = topology.get(enode)
    # VM TBD
    # set_trace()
    node.libs.scapy.send(proto_str, list, "count=3")
    print('Send the packet')
    return None


def sniffpcountpacket(enode, proto_str, list, topology, count):
    node = topology.get(enode)
    eth = node.ports['1']
    recdpacket = node.libs.scapy.sniff2(
                            'iface="' + eth + '", filter="icmp", '
                            'count=3, '
                            'prn=lambda x: x.summary(), timeout=5'
                                        )
    return recdpacket


def sniffudpcountpacket(enode, proto_str, list, topology, count):
    node = topology.get(enode)
    eth = node.ports['1']
    recdpacket = node.libs.scapy.sniff2(
                            'iface="' + eth + '", '
                            'filter="udp and ip src 10.0.10.1", '
                            'count=3, '
                            'prn=lambda x: x.summary(), timeout=5'
                                        )
    return recdpacket


def t4snifficmpcountpacket(enode, proto_str, list, topology):
    node = topology.get(enode)
    eth = node.ports['1']
    recdpacket = node.libs.scapy.sniff2(
                            'iface="' + eth + '", '
                            'filter="icmp and ip src 10.0.10.1", '
                            'prn=lambda x: x.summary(), timeout=5'
                                        )
    return recdpacket


def t1asnifftcpcountpacket(enode, proto_str, list, topology, count):
    node = topology.get(enode)
    eth = node.ports['1']
    recdpacket = node.libs.scapy.sniff2(
                            'iface="' + eth + '", '
                            'filter="tcp and ip src 10.0.10.1", '
                            'count=3, '
                            'prn=lambda x: x.summary(), timeout=5'
                                        )
    return recdpacket

functions = [sendscapypacket, sniffscapypacket, sendscapyl2packet,
             filterscapypacket, sendsr1packet, sendpcountpacket,
             sniffpcountpacket, sniffudpcountpacket,
             t4snifficmpcountpacket, t1asnifftcpcountpacket]


@mark.test_id(10404)
def test_traffic_on_port(topology, step):
    """
    Test traffic after applying ACEs to ports.

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

    ping = hs2.libs.ping.ping(1, '10.0.10.1')

    step('Start scapy on host workstations')
    hs1.libs.scapy.start_scapy()
    hs2.libs.scapy.start_scapy()

    # step('pre-traffic arp and block RST on sender')

    # sr(ARP(pdst='192.168.3.95', psrc='192.168.3.1', op=1))
    # iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
    # iptables -L
    # ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),timeout=2)
    # ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%") )
    # arping("192.168.1.*")
    # set_trace()

    # ether_packet = hs1.libs.scapy.ether("dst='ff:ff:ff:ff:ff:ff'")
    # arp_packet = hs1.libs.scapy.arp("pdst='10.0.10.2', psrc='10.0.10.1'")
    # list_arp = [ether_packet, arp_packet]
    # proto_str = 'Ether/ARP'

    # numfuncs = range(len(functions))

    # txthread = ScapyThread(
    #             functions[3],
    #             'hs1', topology, proto_str, list_arp, functions[0].__name__)
    # rxthread = ScapyThread(
    #             functions[1],
    #             'hs2', topology, '', [], functions[1].__name__)

    # rxthread.start()
    # txthread.start()

    # txthread.join()
    # rxthread.join()

    # print(rxthread.outresult())

    step('################ T1a Apply IPV4 ACL ###########')
    step('################ to interface 1 ###############')
    step('################ any Host  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test5') as ctx:
        ctx.permit(
            '',
            '5', 'tcp', 'any',
            '', 'any', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'5\s+permit\s+tcp\s+any\s+any'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test5')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test5\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )
    set_trace()

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    tcp_packet = hs1.libs.scapy.tcp("dport=179")
    # tcp_packet = hs1.libs.scapy.tcp("dport=80, flags='S'")
    # udp_packet = hs1.libs.scapy.udp("dport=5555")

    list1 = [ip_packet, tcp_packet]
    # proto_str = 'IP/TCP'
    proto_str = 'IP/TCP'

    txthread = ScapyMultiCountThread(
                functions[5],
                'hs1', topology, proto_str, list1, functions[5].__name__)
    rxthread = ScapyMultiCountThread(
                functions[9],
                'hs2', topology, '', [], functions[9].__name__)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()
    print(rxthread.outresult())

    # if rxthread.outresult():
    #     assert search(
    #             ''
    #             r'ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2\s+'
    #             'echo-request'.format(
    #                              **locals()
    #                            ), rxthread.outresult()
    #         )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test5') as ctx:
        ctx.no('5')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test5')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test5\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T1 Apply Permit ACL ###########')
    step('################ to interface ###############')
    step('################ Multiple ICMP and filter ###############')
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

    txthread = ScapyMultiCountThread(
                functions[5],
                'hs1', topology, proto_str, list1, functions[5].__name__)
    rxthread = ScapyMultiCountThread(
                functions[6],
                'hs2', topology, '', [], functions[6].__name__)

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
                functions[8],
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

    step('################ T5 Apply IPV4 ACL ###########')
    step('################ to interface 1 ###############')
    step('################ any Host  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test5') as ctx:
        ctx.permit(
            '',
            '5', '4', 'any',
            '', 'any', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'5\s+permit\s+4\s+any\s+any'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test5')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test5\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    # tcp_packet = hs1.libs.scapy.tcp("sport=22, dport=80")
    # tcp_packet = hs1.libs.scapy.tcp("dport=80, flags='S'")
    udp_packet = hs1.libs.scapy.udp("dport=5555")

    list1 = [ip_packet, udp_packet]
    # proto_str = 'IP/TCP'
    proto_str = 'IP/UDP'

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

    # if rxthread.outresult():
    #     assert search(
    #             ''
    #             r'ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2\s+'
    #             'echo-request'.format(
    #                              **locals()
    #                            ), rxthread.outresult()
    #         )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test5') as ctx:
        ctx.no('5')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test5')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test5\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T9 Apply Permit ACL ###########')
    step('################ to interface ###############')
    step('################ Multiple UDP and filter ###############')
    step('################ A.B.C.D Host  ###############')
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test9') as ctx:
        ctx.permit('', '9', 'udp', '10.0.10.1', '', '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'9\s+permit\s+udp\s+10\.[0-9]\.10\.1'
       '\s+10\.[0-9]\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test9')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test9\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    udp_packet = hs1.libs.scapy.udp("dport=58888")

    list1 = [ip_packet, udp_packet]
    proto_str = 'IP/UDP'
    set_trace()

    numfuncs = range(len(functions))

    txthread = ScapyMultiCountThread(
                functions[5],
                'hs1', topology, proto_str, list1, functions[5].__name__)
    rxthread = ScapyMultiCountThread(
                functions[7],
                'hs2', topology, '', [], functions[6].__name__)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()
    print(rxthread.outresult())
    if rxthread.outresult():
        assert search(
                ''
                r'UDP\s+10\.0\.10\.1:domain\s+\>\s+10\.0\.10\.2:'
                .format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test9') as ctx:
        ctx.no('9')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test9')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test9\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T10 Apply Permit ACL ###########')
    step('################ to interface ###############')
    step('################ Multiple UDP and filter ###############')
    step('################ A.B.C.D/M Host  ###############')
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test10') as ctx:
        ctx.permit('', '10', 'udp', '10.0.10.1/8', '', '10.0.10.2/8', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'10\s+permit\s+udp\s+10\.[0-9]\.10\.1/255\.0\.0\.0'
       '\s+10\.[0-9]\.10\.2/255\.0\.0\.0'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test10')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test10\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    udp_packet = hs1.libs.scapy.udp("dport=58888")

    list1 = [ip_packet, udp_packet]
    proto_str = 'IP/UDP'
    set_trace()

    numfuncs = range(len(functions))

    txthread = ScapyMultiCountThread(
                functions[5],
                'hs1', topology, proto_str, list1, functions[5].__name__)
    rxthread = ScapyMultiCountThread(
                functions[7],
                'hs2', topology, '', [], functions[6].__name__)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()
    print(rxthread.outresult())
    if rxthread.outresult():
        assert search(
                ''
                r'UDP\s+10\.0\.10\.1:domain\s+\>\s+10\.0\.10\.2:'
                .format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test10') as ctx:
        ctx.no('10')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test10')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test10\s+)'.format(
                                         **locals()
                                     ), test1_result
    )
