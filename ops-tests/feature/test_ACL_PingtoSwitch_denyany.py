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
Test_name: test_ACL_PingtoSwitch_denyany
Test_Description: This test will send ping from host to switch and
check if the applied ACL blocks the traffic coming in to the switch
"""
from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division
from pytest import mark
from time import sleep

TOPOLOGY = """
#
# +-------+
# |       |     +-------+
# |  hs1  <----->  sw1  |
# |       |     +-------+
# +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host name="host 1"] hs1

# Links
sw1:1 -- hs1:1
"""

vlan10 = '10'
vlan_ip1 = '100.1.1.1/24'
ip1 = '100.1.1.2'


def ops_config(sw, vlan10, vlan_ip1, step):
    step('### Config DUT setting ###')
    print('\nCreating Vlans on DUT')
    with sw.libs.vtysh.ConfigVlan(vlan10) as ctx:
        ctx.no_shutdown()
    with sw.libs.vtysh.ConfigInterfaceVlan(vlan10) as ctx:
        ctx.no_shutdown()
        ctx.ip_address(vlan_ip1)
    print('\nConfig interface dut interface 1')
    with sw.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.vlan_access(vlan10)
        ctx.no_shutdown()


@mark.platform_incompatible(['docker'])
def test_acl_pingtoswitch_denyany(topology, step):
    sw1 = topology.get('sw1')
    hs1 = topology.get('hs1')

    assert sw1 is not None
    assert hs1 is not None

    # Configure host 1
    print("Configuring host 1 with ip1\n")
    hs1.libs.ip.interface('1', addr='100.1.1.2/24', up=True)
    ops_config(sw1, vlan10, vlan_ip1, step)
    sleep(5)
    # Ping from host 1 to switch
    print("Ping s1 from hs1\n")
    output = hs1.libs.ping.ping(10, "100.1.1.1")
    assert output['transmitted'] == output['received']
    with sw1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('test1')
    with sw1.libs.vtysh.ConfigAccessListIp('test1') as ctx:
        ctx.deny('', '10', 'any', 'any', '', 'any', '')
    with sw1.libs.vtysh.ConfigInterface(1) as ctx:
        ctx.apply_access_list_ip_in('test1')
    print("Ping s1 from hs1\n")
    output = hs1.libs.ping.ping(10, "100.1.1.1")
    assert output['received'] == 0, 'ACL failed to block \
traffic destined to Switch'
    print("ACL blocked traffic destined to switch")
