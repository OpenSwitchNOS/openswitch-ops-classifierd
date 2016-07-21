
def topology_1switch_2host(ops1, hs1, hs2):
    """
    Call this function for 1switch and 2 host topology
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
    Call this function for 2switch and 2 host topology without lag
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


def topology_2switch_2host_lag(ops1, ops2, hs1, hs2):
    """
    Call this function for 2switch and 2 host topology with lag
    sets ports 1, 5 and 6 of both switch1 and switch2 up
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


def config_switch_l2(ops):
    """
    1 Call this function for configuration of one
    Switch (L2 only) (NOT for LAG)
    Configures Interface 1 and 6 for a switch and
    creates VLAN 10 and sets it for interfaces 1 and 6
    """
    config_switch(ops)
    config_vlan(ops)
    with ops.libs.vtysh.ConfigInterface('6') as ctx:
        ctx.vlan_access(10)


def config_2switch_l2(ops1, ops2):
    """
    2 Call this function for configuration of two Switch (L2 only)
    (NOT for LAG)
    Configures Interface 1 and 6 for switch1 and switch2 and
    creates VLAN 10 and sets it for interfaces 1 and 6
    """
    config_switch_l2(ops1)
    config_switch_l2(ops2)


def config_switch_lag_l2(ops1, ops2):
    """
    3 Call this function for configuration of two Switch (L2 only) (LAG)
    Configures Interface 1 and (5&6 FOR lag) for switch1 and switch2 and
    creates VLAN 10 and sets it for interfaces 1 and LAG 10
    """
    config_switch(ops1)
    config_switch(ops2)
    config_vlan(ops1)
    config_vlan(ops2)
    config_additional_port_for_lag(ops1, ops2)
    config_lag_l2(ops1)
    config_lag_l2(ops2)


def config_switch_l3(ops):
    """
    4 Call this function for configuration of one Switch
    (L3 only) (NOT for LAG)
    Configures Interface 1 and 6 for a switch and
    sets IP address to interfaces 1 and 6
    """
    config_switch(ops)
    switch1_interface1_ip_address(ops)
    with ops.libs.vtysh.ConfigInterface('6') as ctx:
        ctx.routing()
        ctx.ip_address('10.10.30.2/24')


def config_switches_l3(ops1, ops2):
    """
    5 Call this function for configuration of two Switch
    (L3 only) (NOT for LAG)
    Configures Interface 1 and 6 for a switch and
    sets IP address to interfaces 1 and 6
    """
    config_switch(ops1)
    config_switch(ops2)
    switch1_interface1_ip_address(ops1)
    switch2_interface1_ip_address(ops2)
    with ops1.libs.vtysh.ConfigInterface('6') as ctx:
        ctx.routing()
        ctx.ip_address('10.10.20.1/24')
    with ops2.libs.vtysh.ConfigInterface('6') as ctx:
        ctx.routing()
        ctx.ip_address('10.10.20.2/24')
    ip_route_switch1(ops1)
    ip_route_switch2(ops2)


def config_switches_l3_lag(ops1, ops2):
    """
    6 Call this function for configuration of two Switch (L3 only) (for LAG)
    Configures Interface 1 (5&6 FOR lag) for switch1 and switch2  and
    sets IP address to interfaces 1 and lag 10
    """
    config_switch(ops1)
    config_switch(ops2)
    config_additional_port_for_lag(ops1, ops2)
    switch1_interface1_ip_address(ops1)
    switch2_interface1_ip_address(ops2)
    config_lag(ops1)
    config_lag(ops2)
    with ops1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.routing()
        ctx.ip_address('10.10.20.1/24')
    with ops2.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.routing()
        ctx.ip_address('10.10.20.2/24')
    ip_route_switch1(ops1)
    ip_route_switch2(ops2)


def config_hosts_l2(hs1, hs2):
    """
    Call this function for configuration of host(L2 only)
    """
    hs1.libs.ip.interface('1', up=False)
    hs2.libs.ip.interface('1', up=False)
    hs1.libs.ip.interface('1', addr='10.10.10.1/24', up=True)
    hs2.libs.ip.interface('1', addr='10.10.10.2/24', up=True)


def config_hosts_l3(hs1, hs2):
    """
    Call this function for configuration of host(L3 only)
    """
    hs1.libs.ip.interface('1', up=False)
    hs2.libs.ip.interface('1', up=False)
    hs1.libs.ip.interface('1', addr='10.10.10.1/24', up=True)
    hs2.libs.ip.interface('1', addr='10.10.30.1/24', up=True)
    hs1("ip route add default via 10.10.10.2")
    hs2("ip route add default via 10.10.30.2")


def ping_test_l2(hs1):
    """
    Call this function for ping test with L2 config
    """
    ping = hs1.libs.ping.ping(1, '10.10.10.2')
    assert ping['transmitted'] == ping['received'] == 1


def ping_test_l3(hs1):
    """
    Call this function for ping test with L3 config
    """
    ping = hs1.libs.ping.ping(1, '10.10.30.1')
    assert ping['transmitted'] == ping['received'] == 1


def start_scapy_on_hosts(hs1, hs2):
    """
    Call this function before starting scapy
    """
    hs1.libs.scapy.start_scapy()
    hs2.libs.scapy.start_scapy()


def config_vlan(ops):
    """
    This function is already called
    It creates vlan 10 and sets it to interface 1
    """
    with ops.libs.vtysh.ConfigVlan('10') as ctx:
        ctx.no_shutdown()
    with ops.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.vlan_access(10)


def config_switch(ops):
    """
    This function is already called
    It sets interfaces 1 and 6 of a switch to "no shutdown and no routing"
    It is called in functions 1. config_switch(ops)_l2
    """
    with ops.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    with ops.libs.vtysh.ConfigInterface('6') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()


def config_additional_port_for_lag(ops1, ops2):
    """
    This function is already called
    It sets new interface 5 to "no shutdown and no routing for LAG"
    It is called by functions 1. config_additional_port_for_lag_l2 and
     2. config_additional_port_for_lag_l3
    """
    with ops1.libs.vtysh.ConfigInterface('5') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    with ops2.libs.vtysh.ConfigInterface('5') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()


def config_lag(ops):
    """
    This function is already called
    It creates lag10 and sets it to interfaces 5 and interface 6 of a switch
    """
    with ops.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.no_shutdown()

    with ops.libs.vtysh.ConfigInterface('5') as ctx:
        ctx.lag(10)
    with ops.libs.vtysh.ConfigInterface('6') as ctx:
        ctx.lag(10)


def config_lag_l2(ops):
    """
    This function is already called
    Creates Interface lag 10 for a switch and sets VLAN 10 to the lag10
    """
    config_lag(ops)
    with ops.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.no_routing()
        ctx.vlan_access(10)


def switch1_interface1_ip_address(ops1):
    """
    This function is already called
    It sets IP address for interface1 of switch1
    """
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.routing()
        ctx.ip_address('10.10.10.2/24')


def switch2_interface1_ip_address(ops2):
    """
    This function is already called
    It sets IP address for interface1 of switch2
    """
    with ops2.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.routing()
        ctx.ip_address('10.10.30.2/24')


def ip_route_switch1(ops1):
    """
    This function is already called
    It sets IP route for switch1
    """
    ops1("configure terminal")
    ops1("ip route 10.10.30.0/24 10.10.20.2")
    ops1("exit")


def ip_route_switch2(ops2):
    """
    This function is already called
    It sets IP route for switch2
    """
    ops2("configure terminal")
    ops2("ip route 10.10.10.0/24 10.10.20.1")
    ops2("exit")
