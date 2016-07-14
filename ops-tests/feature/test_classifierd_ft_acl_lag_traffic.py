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
Open Switch test with configuring LAG and ACL
"""

from pytest import mark
from topology_lib_scapy.library import ScapyThread
from topology_lib_scapy.library import send_traffic
from topology_lib_scapy.library import sniff_traffic
from re import findall
from time import sleep
from re import search


TOPOLOGY = """
# +-------+                                     +-------+
# |       |     +--------+     +-------+        |       |
# | host1 <-----> switch1 <---->switch2<------->| host2 |
# |       |     +--------+     +-------+        |       |
# +-------+                                     +-------+

#Nodes
[type=openswitch name="openswitch 1"] switch1
[type=openswitch name="openswitch 2"] switch2
[type=host name="Host 1"] host1
[type=host name="Host 2"] host2

#Links
host1:1 -- switch1:6
switch1:1 -- switch2:1
switch1:2 -- switch2:2
switch2:6 -- host2:1
"""


def acl_permit_icmp_any_any(switch2, host1, host2, topology):
    # Configuring an ACL to permit any ICMP traffic
    with switch2.libs.vtysh.ConfigAccessListIpTestname('acl_icmp') as ctx:
        ctx.permit('', '10', 'icmp', 'any', '', 'any', '')
    show_run = switch2('show run')

    assert search(
        ""
        r'10\s+permit\s+icmp\s+any\s+any'.format(
                                            **locals()
                                        ), show_run
    )
    # Apply ACL on switch2 and verify it
    with switch2.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.apply_access_list_ip_in('acl_icmp')

    show_run = switch2('show access-list interface lag10 commands')

    assert search(
        ""
        r'apply\s+access-list\s+ip\s+acl_icmp\s+in'.format(
                                                        **locals()
                                                    ), show_run
    )

    # Creating 10 ICMP packet
    count = 10
    port_str = '1'
    timeout = 25
    ip_packet = host1.libs.scapy.ip("dst='10.10.20.2', src='10.10.10.2'")
    icmp_packet = host1.libs.scapy.icmp()
    filter_icmp = (
                    "lambda p: ICMP in p and p[IP].src == '10.10.10.2' "
                    "and p[IP].dst == '10.10.20.2'"
                )
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'host1', topology, proto_str, list_icmp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'host2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    # Passing ICMP traffic from host1 to host2
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    # Verify ICMP packets received
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[2] == '10')
    # Removing Config
    with switch2.libs.vtysh.ConfigAccessListIpTestname('acl_icmp') as ctx:
        ctx.no('10')

    with switch2.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('acl_icmp')

    switch2('show run')


def acl_deny_icmp_any_any(switch2, host1, host2, topology):
    # Configuring an ACL to deny any ICMP traffic
    with switch2.libs.vtysh.ConfigAccessListIpTestname('acl_icmp2') as ctx:
        ctx.deny('', '10', 'icmp', 'any', '', 'any', '')
    show_run = switch2('show run')

    assert search(
        ""
        r'10\s+deny\s+icmp\s+any\s+any'.format(
                                            **locals()
                                        ), show_run
    )
    # Apply ACL on switch2 and verify it
    with switch2.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.apply_access_list_ip_in('acl_icmp2')

    show_run = switch2('show access-list interface lag10 commands')

    assert search(
        ""
        r'apply\s+access-list\s+ip\s+acl_icmp2\s+in'.format(
                                                        **locals()
                                                    ), show_run
    )

    # Creating 10 ICMP packet
    count = 10
    port_str = '1'
    timeout = 25
    ip_packet = host1.libs.scapy.ip("dst='10.10.20.2', src='10.10.10.2'")
    icmp_packet = host1.libs.scapy.icmp()
    filter_icmp = (
                    "lambda p: ICMP in p and p[IP].src == '10.10.10.2' "
                    "and p[IP].dst == '10.10.20.2'"
                )
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'host1', topology, proto_str, list_icmp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'host2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    # Passing ICMP traffic from host1 to host2
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    # Verify ICMP packets received
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[2] == '0')
    # Removing Config
    with switch2.libs.vtysh.ConfigAccessListIpTestname('acl_icmp2') as ctx:
        ctx.no('10')

    with switch2.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('acl_icmp2')

    switch2('show run')


def wait_until_interface_up(switch, portlbl, timeout=30, polling_frequency=1):
    """
    Wait until the interface, as mapped by the given portlbl, is marked as up.

    :param switch: The switch node.
    :param str portlbl: Port label that is mapped to the interfaces.
    :param int timeout: Number of seconds to wait.
    :param int polling_frequency: Frequency of the polling.
    :return: None if interface is brought-up. If not, an assertion is raised.
    """
    for i in range(timeout):
            status = switch.libs.vtysh.show_interface(portlbl)
            if status['interface_state'] == 'up':
                break
            sleep(polling_frequency)
    else:
        assert False, (
            'Interface {}:{} never brought-up after'
            'waiting for {} seconds'.format(
                switch.identifier, portlbl, timeout
                )
            )


def setting_interface_enabled(switch1, switch2, p11, p12, p16, p21, p22, p26):
    # setting interfaces enabled
    assert not switch1(
        'set interface {p11} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )

    assert not switch1(
        'set interface {p12} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )

    assert not switch1(
        'set interface {p16} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )

    assert not switch2(
        'set interface {p21} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )

    assert not switch2(
        'set interface {p22} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )

    assert not switch2(
        'set interface {p26} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )


def configure_switch1(switch1):
    # configuring switch 1
    with switch1.libs.vtysh.ConfigInterface('6') as ctx:
        ctx.no_shutdown()
        ctx.ip_address('10.10.10.1/24')

    with switch1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.no_shutdown()
        ctx.ip_address('10.10.30.1/24')

    with switch1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_shutdown()
        ctx.lag('10')

    with switch1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.no_shutdown()
        ctx.lag('10')
    switch1("configure terminal")
    switch1("ip route 10.10.20.0/24 10.10.30.2")
    switch1("exit")


def configure_switch2(switch2):
    # configuring switch 2
    with switch2.libs.vtysh.ConfigInterface('6') as ctx:
        ctx.no_shutdown()
        ctx.ip_address('10.10.20.1/24')

    with switch2.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.no_shutdown()
        ctx.ip_address('10.10.30.2/24')

    with switch2.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_shutdown()
        ctx.lag('10')

    with switch2.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.no_shutdown()
        ctx.lag('10')
    switch2("configure terminal")
    switch2("ip route 10.10.10.0/24 10.10.30.1")
    switch2("exit")


def configure_hosts(host1, host2):
    # Configuring Hosts
    host1.libs.ip.interface('1', up=False)
    host2.libs.ip.interface('1', up=False)
    host1.libs.ip.interface('1', addr='10.10.10.2/24', up=True)
    host2.libs.ip.interface('1', addr='10.10.20.2/24', up=True)
    host1("ip route add default via 10.10.10.1")
    host2("ip route add default via 10.10.20.1")


@mark.platform_incompatible(['docker'])
def test_lagacl(topology):

    switch1 = topology.get('switch1')
    switch2 = topology.get('switch2')
    host1 = topology.get('host1')
    host2 = topology.get('host2')

    assert host1 is not None
    assert host2 is not None
    assert switch1 is not None
    assert switch2 is not None

    p11 = switch1.ports['1']
    p12 = switch1.ports['2']
    p16 = switch1.ports['6']
    p21 = switch2.ports['1']
    p22 = switch2.ports['2']
    p26 = switch2.ports['6']

    # setting interfaces enabled
    setting_interface_enabled(switch1, switch2, p11, p12, p16, p21, p22, p26)

    # configuring switch 1
    configure_switch1(switch1)

    # configuring switch 2
    configure_switch2(switch2)

    # Configuring hosts
    configure_hosts(host1, host2)

    # Wait until interfaces are up
    for switch, portlbl in [(switch1, '1'), (switch1, '2'), (switch1, '6')]:
        wait_until_interface_up(switch, portlbl)
    for switch, portlbl in [(switch2, '1'), (switch2, '2'), (switch2, '6')]:
        wait_until_interface_up(switch, portlbl)

    # Starting Scapy
    host1.libs.scapy.start_scapy()
    host2.libs.scapy.start_scapy()
    # Test case1 : To permit any icmp traffic
    acl_permit_icmp_any_any(switch2, host1, host2, topology)
    # Test case2 : To deny any icmp traffic
    acl_deny_icmp_any_any(switch2, host1, host2, topology)
