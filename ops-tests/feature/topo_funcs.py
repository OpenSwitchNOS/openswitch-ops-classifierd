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
import time


def topology_1switch_2host(ops1, hs1, hs2):
    """
    Setting up one switch and two host topology
    sets ports 1 and 6 up
    """
    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    p1 = ops1.ports['1']
    p2 = ops1.ports['6']

    # Mark interfaces as enabled
    assert not ops1(
        'set interface {p1} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p2} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )


def topology_2switch_2host(ops1, ops2, hs1, hs2):
    """
    Setting up two switch and two host topology without lag
    sets ports 1 and 5 of both switch1 and switch2 up
    """
    topology_1switch_2host(ops1, hs1, hs2)

    assert ops2 is not None

    p21 = ops2.ports['1']
    p22 = ops2.ports['6']

    assert not ops2(
        'set interface {p21} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not ops2(
        'set interface {p22} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )


def topology_2switch_lag(ops1, ops2):
    """
    Setting up two switch host topology with lag
    sets ports 5 and 6 of both switch1 and switch2 up
    """
    assert ops1 is not None
    assert ops2 is not None

    p11 = ops1.ports['5']
    p12 = ops1.ports['6']
    p21 = ops2.ports['5']
    p22 = ops2.ports['6']

    assert not ops1(
        'set interface {p11} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p12} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )

    assert not ops2(
        'set interface {p21} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not ops2(
        'set interface {p22} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )


def topology_2switch_2host_lag(ops1, ops2, hs1, hs2):
    """
    Setting up two switch and two host topology with lag
    sets ports 1, 5 and 6 of both switch1 and switch-2 up
    """
    topology_2switch_2host(ops1, ops2, hs1, hs2)
    p15 = ops1.ports['5']
    p25 = ops2.ports['5']

    assert not ops1(
        'set interface {p15} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not ops2(
        'set interface {p25} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )


def config_switch_l2(ops, vlan_id, ifaclist=['1', '6']):
    """
    1 Configuration of one
    Switch (L2 only) (NOT for LAG)
    Configures Interface 1 and 6 for a switch and
    creates VLAN and sets it for interfaces 1 and 6
    """
    config_switch_no_shut_no_route(ops, ifaclist)
    config_vlan(ops, vlan_id)
    with ops.libs.vtysh.ConfigInterface(ifaclist[1]) as ctx:
        ctx.vlan_access(vlan_id)


def config_2switch_l2(
    ops1, ops2, vlan_id1, vlan_id2, ifaclist=['1', '6']
        ):
    """
    2 Configuration of two Switch (L2 only)
    (NOT for LAG)
    Configures Interface 1 and 6 for switch1 and switch2 and
    creates VLAN and sets it for interfaces 1 and 6
    """
    config_switch_l2(ops1, vlan_id1, ifaclist)
    config_switch_l2(ops2, vlan_id2, ifaclist)


def config_switch_lag_l2(
                        ops1, ops2, vlan_id1, vlan_id2,
                        lag_id1, lag_id2, interface_list=['5', '6'],
                        non_lag_iface='1'
                        ):
    """
    3 Configuration of two Switch (L2 only) (LAG)
    Configures Interface 1 and (5&6 FOR lag) for switch1 and switch2 and
    creates VLAN and sets it for interfaces 1 and LAG
    """
    config_switch_no_shut_no_route(ops1, interface_list)
    config_switch_no_shut_no_route(ops2, interface_list)
    config_switch_no_shut_no_route(ops1, [non_lag_iface])
    config_switch_no_shut_no_route(ops2, [non_lag_iface])
    config_vlan(ops1, vlan_id1, [non_lag_iface], True)
    config_vlan(ops2, vlan_id2, [non_lag_iface], True)
    config_lag_l2(ops1, vlan_id1, lag_id1, interface_list)
    config_lag_l2(ops2, vlan_id2, lag_id2, interface_list)


def config_switch_l3(ops, ip1, ip2, ifaclist=['1', '6']):
    """
    4 Configuration of one Switch
    (L3 only) (NOT for LAG)
    Configures Interface 1 and 6 for a switch and
    sets IP address to interfaces 1 and 6
    """
    config_interface_state(ops, 'port', ifaclist, True)
    switch_interface_ip_address(ops, ifaclist[0], ip1)
    switch_interface_ip_address(ops, ifaclist[1], ip2)


def config_switches_l3(
                    ops1, ops2, ip_ops1_int1, ip_ops2_int1, ip_ops1_int6,
                    ip_ops2_int6, ip_route_ops1, ip_route_ops2,
                    ifaclist=['1', '6']
                     ):
    """
    5 Configuration of two Switch
    (L3 only) (NOT for LAG)
    Configures Interface 1 and 6 for a switch and
    sets IP address to interfaces 1 and 6
    """
    config_interface_state(ops1, 'port', ifaclist, True)
    config_interface_state(ops2, 'port', ifaclist, True)
    switch_interface_ip_address(ops1, ifaclist[0], ip_ops1_int1)
    switch_interface_ip_address(ops2, ifaclist[0], ip_ops2_int1)
    switch_interface_ip_address(ops1, ifaclist[1], ip_ops1_int6)
    switch_interface_ip_address(ops2, ifaclist[1], ip_ops2_int6)
    ip_route_switch(ops1, ip_route_ops1)
    ip_route_switch(ops2, ip_route_ops2)


def config_switches_l3_lag(
                ops1, ops2, ip_ops1_int1, ip_ops2_int1, ip_ops1_lag,
                ip_ops2_lag, ip_route_ops1, ip_route_ops2, lag_id1,
                lag_id2, interface_list=['5', '6'], non_lag_iface='1'
                ):
    """
    6 Configuration of two Switch (L3 only) (for LAG)
    Configures Interface 1, interfaces int interface_list
    (default 5&6 FOR lag) for switch1 and switch2  and
    sets IP address to interfaces 1 and lag
    """
    switch_interface_ip_address(ops1, non_lag_iface, ip_ops1_int1)
    switch_interface_ip_address(ops2, non_lag_iface, ip_ops2_int1)
    config_lag(ops1, lag_id1, interface_list)
    config_lag(ops2, lag_id1, interface_list)
    with ops1.libs.vtysh.ConfigInterfaceLag(lag_id1) as ctx:
        ctx.ip_address(ip_ops1_lag)
    with ops2.libs.vtysh.ConfigInterfaceLag(lag_id2) as ctx:
        ctx.ip_address(ip_ops2_lag)
    ip_route_switch(ops1, ip_route_ops1)
    ip_route_switch(ops2, ip_route_ops2)


def config_hosts_l2(hs1, hs2, ip_hs1, ip_hs2):
    """
    Configuration of host (L2 only)
    """
    hs1.libs.ip.interface('1', up=False)
    hs2.libs.ip.interface('1', up=False)
    hs1.libs.ip.interface('1', addr=ip_hs1, up=True)
    hs2.libs.ip.interface('1', addr=ip_hs2, up=True)


def config_hosts_l3(
                hs1, hs2, ip_hs1, ip_hs2,
                ip_route_hs1, ip_route_hs2
                ):
    """
    Configuration of host (L3 only)
    """
    hs1.libs.ip.interface('1', up=False)
    hs2.libs.ip.interface('1', up=False)
    hs1.libs.ip.interface('1', addr=ip_hs1, up=True)
    hs2.libs.ip.interface('1', addr=ip_hs2, up=True)
    hs1(ip_route_hs1)
    hs2(ip_route_hs2)


def ping_test(host, ip):
    """
    Ping test with L2 config
    """
    ping = host.libs.ping.ping(1, ip)
    print(ping)
    assert ping['transmitted'] == ping['received'] == 1


def start_scapy_on_hosts(hs1, hs2):
    """
    Install and start scapy on hosts
    """
    # Having problems with starting scapy sometimes.  The work around is to
    # try at the most twice
    for host in [hs1, hs2]:
        print("Starting scapy for <%s>" % (host.identifier))
        try:
            host.libs.scapy.start_scapy()
        except Exception as err:
            print("Failed to start scapy for <%s> because <%s>, trying again"
                  % (host.identifier, err))
            host.libs.scapy.start_scapy()


def config_vlan(ops, vlan_id, interface_list=['1'], enable=True):
    """
    Creates/delete vlan and sets it to all interfaces in interface_list
    (default value '1')
    """
    if enable:
        with ops.libs.vtysh.ConfigVlan(vlan_id) as ctx:
            ctx.no_shutdown()
        for interface_id in interface_list:
            with ops.libs.vtysh.ConfigInterface(interface_id) as ctx:
                ctx.vlan_access(vlan_id)
    else:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.no_vlan(vlan_id)


def config_switch_no_shut_no_route(ops, interface_list):
    """
    Sets interfaces 1 and 6 of a switch to "no shutdown and no routing"
    """
    for interface in interface_list:
        with ops.libs.vtysh.ConfigInterface(interface) as ctx:
            ctx.no_routing()
            ctx.no_shutdown()


def update_lag_members(ops, interface_list, lag_id, add_or_remove):
    """
    Add/Remove lag members to an existing lag.
    NOTE - Lag needs to be created before using this function
           to create lag, use function config_lag
    """
    assert ops is not None
    assert isinstance(lag_id, int)
    assert isinstance(interface_list, list)
    assert isinstance(add_or_remove, bool)
    if add_or_remove:
        for interface in interface_list:
            assert isinstance(interface, str)
            with ops.libs.vtysh.ConfigInterface(interface) as ctx:
                ctx.lag(lag_id)
            """
            verify whether lag member is added
            """
            result = ops('show running-config interface ' +
                         ops.ports[interface])
            print(result)
            assert 'lag '+str(lag_id) in result

    else:
        for interface in interface_list:
            assert isinstance(interface, str)
            with ops.libs.vtysh.ConfigInterface(interface) as ctx:
                ctx.no_lag(lag_id)
            """
            verify whether lag member is removed
            """
            print('interface '+ops.ports[interface])
            command = 'show running-config interface ' + ops.ports[interface]
            print(command)
            result = ops(command)
            print('running interface \n'+result)
            # assert 'lag '+str(lag_id) not in result
    time.sleep(5)


def config_lag(ops, lag_id, interface_list=['5', '6'], enable=True):
    """
    Create/Delete a lag. After creation add
    a list of interfaces (default value 5 and 6).
    NOTE - interface needs to be up for this operation
    """
    assert ops is not None
    assert isinstance(lag_id, int)
    assert isinstance(interface_list, list)
    assert isinstance(enable, bool)

    if enable:
        config_interface_state(ops, 'port', interface_list, True)
        with ops.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
            ctx.no_shutdown()
        for interface in interface_list:
            assert isinstance(interface, str)
            with ops.libs.vtysh.ConfigInterface(interface) as ctx:
                ctx.lag(lag_id)
            """
            verify whether lag member is added
            """
            result = ops('show running-config interface ' +
                         str(ops.ports[interface]))
            assert 'lag '+str(lag_id) in result
    else:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.no_interface_lag(str(lag_id))
        """
        verify whether lag is removed
        """
        result = ops('show run')
        print(result)
        assert 'lag '+str(lag_id) not in result


def config_lag_l2(ops, vlan_id, lag_id, interface_list=['5', '6']):
    """
    Creates Interface lag 10 for a switch and sets VLAN 10 to the lag10
    also create vlan and enable interface if not done before
    """
    config_lag(ops, lag_id, interface_list, True)
    config_vlan(ops, vlan_id, [], enable=True)
    with ops.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.no_routing()
        ctx.vlan_access(vlan_id)


def switch_interface_ip_address(ops, iface, ip):
    """
    Sets IP address for interface1 of switch2
    """
    with ops.libs.vtysh.ConfigInterface(iface) as ctx:
        ctx.ip_address(ip)
    time.sleep(5)


def ip_route_switch(ops1, ip_route):
    """
    Sets IP route for switch-1
    """
    ops1("configure terminal")
    ops1(ip_route)
    ops1("exit")


def config_interface_state(ops, interface_type, interface_list, enable):

    assert ops is not None
    assert interface_type in ('vlan', 'port', 'lag')
    assert isinstance(interface_list, list)
    assert isinstance(enable, bool)

    for interface in interface_list:
        if interface_type == 'port':
            assert isinstance(interface, str)
            with ops.libs.vtysh.ConfigInterface(interface) as ctx:
                ctx.no_shutdown() if enable else ctx.shutdown()

        if interface_type == 'lag':
            assert isinstance(interface, int)
            with ops.libs.vtysh.ConfigInterfaceLag(interface) as ctx:
                ctx.no_shutdown() if enable else ctx.shutdown()

        if interface_type == 'vlan':
            assert isinstance(interface, int)
            with ops.libs.vtysh.ConfigVlan(interface) as ctx:
                ctx.no_shutdown() if enable else ctx.shutdown()
    time.sleep(5)


def config_port_routing(ops, interface_list, enable):

    assert ops is not None
    assert isinstance(interface_list, list)
    assert isinstance(enable, bool)

    for interface in interface_list:
        with ops.libs.vtysh.ConfigInterface(interface) as ctx:
            ctx.routing() if enable else ctx.no_routing()
    time.sleep(5)
