
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
OpenSwitch traffic Tests for LAG with ACLs - L2
This file consists of the following test cases
Test 1 : acl_on_lag_with_members
Test 2 : acl_on_lag_with_one_member
Test 3 : acl_on_lag_with_no_members
Test 4 : acl_on_lag_with_shut_on_one_member
Test 5 : acl_on_lag_with_shut_on_all_members
Test 6 : acl_on_lag_with_shut_on_lag
Test 7 : lag_with_no_member_apply_acl
Test 8 : lag_with_no_members_one_acl_add_member
Test 9 : bring_down_lag_members_using_pspo_infra
Test 10: config_persistence
Test 11: replace_acl_when_lag_is_shutdown
Test 12: replace_acl
Test 13.1: egress_acl_on_lag_with_members
Test 13.2: egress_acl_on_lag_with_one_member
Test 13.3: egress_acl_on_lag_with_no_member
Test 13.4: egress_acl_on_lag_with_shut_on_one_member
Test 13.5: egress_acl_on_lag_with_shut_on_all_member
Test 13.6: egress_acl_on_lag_with_shut_on_lag
Test 13.7: egress_lag_with_no_member_apply_acl
Test 13.8: egress_lag_with_no_members_one_acl_add_member
Test 13.9: egress_config_persistence
Test 13.10: egress_replace_acl_when_lag_is_shutdown
Test 13.11: egress_replace_acl_out
Test 14 : lag_members_brought_up_through_pspo_infra_by_removing_from_lag
Test 15 : lag_members_brought_up_through_pspo_infra_by_removing_acl
Test 16 : config_persistence_lag_members_are_down_by_pspo_infra
Test 17 : lag_with_no_members_one_acl_add_and_remove_members
Test 18 : acl_with_lag_and_delete_lag_and_create_new_lag
"""

from pytest import mark
from pytest import fixture
from time import sleep
from acl_classifier_common_lib import apply_acl
from acl_classifier_common_lib import unapply_acl
from acl_classifier_common_lib import create_acl_with_random_aces
from acl_classifier_common_lib import unconfigure_acl
from acl_classifier_common_lib import reboot_switch
from acl_classifier_common_lib import verify_interface_hw_status
from acl_classifier_common_lib import configure_acl_l3
from acl_classifier_common_lib import create_and_verify_traffic
from topo_funcs import topology_2switch_2host_lag
from topo_funcs import config_hosts_l2
from topo_funcs import config_lag
from topo_funcs import config_lag_l2
from topo_funcs import config_vlan
from topo_funcs import config_interface_state
from topo_funcs import update_lag_members
from topo_funcs import config_switch_lag_l2
from topo_funcs import start_scapy_on_hosts
import time


TOPOLOGY = """
# +-------+                                     +-------+
# |       |     +--------+     +-------+        |       |
# | host1 <-----> switch1 <---->switch2<------->| host2 |
# |       |     +--------+     +-------+        |       |
# +-------+                                     +-------+

# Nodes
[type=openswitch name="openswitch 1"] ops1
[type=openswitch name="openswitch 2"] ops2
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

# Links
hs1:if01 -- ops1:if01
ops1:if05 -- ops2:if05
ops1:if06 -- ops2:if06
ops2:if01 -- hs2:if01
"""

filter_str = (
            "lambda p: ICMP in p and p[IP].src == '10.10.10.1' "
            "and p[IP].dst == '10.10.10.2'"
            )

filter_str_reverse = (
                    "lambda p: ICMP in p and p[IP].src == '10.10.10.2' "
                    "and p[IP].dst == '10.10.10.1'"
                    )

filter_str_udp = (
                "lambda p: UDP in p and p[IP].src == '10.10.10.1' "
                "and p[IP].dst == '10.10.10.2'"
                )

filter_str_reverse_udp = (
                    "lambda p: UDP in p and p[IP].src == '10.10.10.2' "
                    "and p[IP].dst == '10.10.10.1'"
                        )

filter_str_tcp = (
                "lambda p: TCP in p and p[IP].src == '10.10.10.1' "
                "and p[IP].dst == '10.10.10.2'"
                )

ip_hs1 = '10.10.10.1'
ip_hs2 = '10.10.10.2'
ip_hs1_bitlength = '10.10.10.1/24'
ip_hs2_bitlength = '10.10.10.2/24'
vlan_id_s1 = 10
vlan_id_s2 = 10
lag_id_s1 = 100
lag_id_s2 = 100
acl_name1 = 'testACL'
acl_name2 = 'test_new'
interface_list = ['if05', 'if06']
max_no_of_aces = 512


@fixture(scope='module')
def configure_lag_l2(request, topology):
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    """ Setup interfaces 5 and 6 of both switches """
    topology_2switch_2host_lag(ops1, ops2, hs1, hs2)
    config_hosts_l2(hs1, hs2, ip_hs1_bitlength, ip_hs2_bitlength)
    # starting scapy on hosts 1 and 2
    start_scapy_on_hosts(hs1, hs2)


@mark.platform_incompatible(['docker'])
def test_acl_on_lag_with_members(configure_lag_l2, topology, step):

    """
    Creating LAG, adding members, applying ACL to it and sending traffic
    """
    step("*****TEST CASE 1*******")
    step("****test for lag with members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(6)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1, lag_id_s2,
                      vlan_id_s2)


@mark.platform_incompatible(['docker'])
def test_acl_on_lag_with_one_member(configure_lag_l2, topology, step):

    """
    Creating LAG, adding members, applying ACL to it,
    removing LAG on one member and sending traffic
    """
    step("*****TEST CASE 2*******")
    step("****test for no lag on one member*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(6)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # removing one member from lag of both the switches
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, False)

    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )

    # tear down
    teardown_topology(ops1, [interface_list[1]], '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, [interface_list[1]], 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 2*******")


@mark.platform_incompatible(['docker'])
def test_acl_on_lag_with_no_members(configure_lag_l2, topology, step):

    """
    Creating LAG, adding members, applying ACL to it,
    removing LAG on all members and sending traffic
    """
    step("*****TEST CASE 3*******")
    step("****test for no lag on all members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(6)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # removing all members from lag of both the switches
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)

    """
    Both the members are removed from LAG, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    # reverse trafficcreate_and_verify_traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    # tear down
    teardown_topology(ops1, [], '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, [], 'ip', acl_name1, lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 3*******")


@mark.platform_incompatible(['docker'])
def test_acl_on_lag_with_shut_on_one_member(configure_lag_l2, topology, step):

    """
    Creating LAG, adding members, applying ACL to it,
    shutting down one member from LAG and sending traffic
    """
    step("*****TEST CASE 4*******")
    step("****test for shut on some member*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(6)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # shut one member from lag of both the switches
    config_interface_state(ops1, 'port', [interface_list[1]], False)
    config_interface_state(ops2, 'port', [interface_list[1]], False)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )

    # No shut the member from lag of both the switches
    config_interface_state(ops1, 'port', [interface_list[1]], True)
    config_interface_state(ops2, 'port', [interface_list[1]], True)
    sleep(5)

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1, lag_id_s2,
                      vlan_id_s2)

    step("*****END OF TEST CASE 4*******")


@mark.platform_incompatible(['docker'])
def test_acl_on_lag_with_shut_on_all_members(configure_lag_l2,
                                             topology, step):

    """
    Creating LAG, adding members, applying ACL to it,
    shutting down all members from LAG and sending traffic
    """
    step("*****TEST CASE 5*******")
    step("****test for shut on all member*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(6)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # shut all members from lag of both the switches
    config_interface_state(ops1, 'port', interface_list, False)
    config_interface_state(ops2, 'port', interface_list, False)

    """
    Both the members of LAG are shutdown, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    # No shut all lag members of both the switches
    config_interface_state(ops1, 'port', interface_list, True)
    config_interface_state(ops2, 'port', interface_list, True)
    sleep(5)

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 5*******")


@mark.platform_incompatible(['docker'])
def test_acl_on_lag_with_shut_on_lag(configure_lag_l2, topology, step):

    """
    Creating LAG, adding members, applying ACL to it,
    shutting down the LAG and sending traffic
    """
    step("*****TEST CASE 6*******")
    step("****test for shutting lag*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(6)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # shut lag
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    config_interface_state(ops2, 'lag', [lag_id_s2], False)

    """
    LAG is shutdown, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    # No shut on lag
    config_interface_state(ops1, 'lag', [lag_id_s1], True)
    config_interface_state(ops2, 'lag', [lag_id_s2], True)
    sleep(5)

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s2)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 6*******")


@mark.platform_incompatible(['docker'])
def test_lag_with_no_member_apply_acl(configure_lag_l2, topology, step):

    """
    Creating LAG with no member, applying ACL to it and sending traffic
    """
    step("*****TEST CASE 7*******")
    step("****test for lag with no members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    """
    LAG has no members, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(
        ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in',
        suppress_warning=True
        )
    sleep(6)
    """
    LAG has no members, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, [], 'ip', acl_name1, lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 7*******")


@mark.platform_incompatible(['docker'])
def test_lag_with_no_members_one_acl_add_member(
                                        configure_lag_l2, topology, step
                                        ):

    """
    Creating LAG with no member, applying ACL,
    adding member to it and sending traffic
    """
    step("*****TEST CASE 8*******")
    step("****test for lag with no members and one acl is success*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    update_lag_members(ops2, interface_list, lag_id_s2, False)
    """
    LAG has no members, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(
        ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in',
        suppress_warning=True
        )
    sleep(6)
    update_lag_members(ops2, interface_list, lag_id_s2, True)
    sleep(6)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 8*******")


@mark.platform_incompatible(['docker'])
def test_bring_down_lag_members_using_pspo_infra(
                                        configure_lag_l2, topology, step
                                        ):

    """
    Creating an ACL(511 entries), applying it to a member,
    Creating LAG with no member, applying ACL, adding member.
    Members are brought down by PSPO Infra
    """
    step("*****TEST CASE 9*******")
    step("****test for PSPO Infra down*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # create an ACL with 512 entries
    create_acl_with_random_aces(ops2, acl_name2, max_no_of_aces)
    apply_acl(ops2, 'port', 'if01', 'ip', acl_name2, 'in')
    sleep(6)
    """
    LAG has no members, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(
        ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in',
        suppress_warning=True
        )
    sleep(6)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, True)
    sleep(6)

    # checking ovsdb status in hardware
    verify_interface_hw_status(ops2, 1)

    """
    LAG members are broughtdown by PSPO infra, so no traffic is sent
    through the switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    # tear down
    unapply_acl(ops2, 'port', 'if01', 'ip', acl_name2, 'in')
    sleep(5)
    unapply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(5)

    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, [interface_list[0]], 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 9*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_config_persistence(configure_lag_l2, topology, step):

    """
    Creating LAG with members, applying ACL,
    copying it to startup config and sending traffic
    """
    step("*****TEST CASE 10*******")
    step("****test for copy acl to startup config*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # copy from running to startup config
    ops2.libs.vtysh.copy_running_config_startup_config(
                                            _shell_args={'timeout': 60}
                                            )
    step("**done copying to startup config**")

    sleep(60)
    print("Rebooting Switch")
    reboot_switch(ops2, shell="vtysh")
    sleep(60)
    step("**reboot completed**")
    # ops2('show run')
    # tear down
    sleep(10)
    ops2.libs.vtysh.erase_startup_config(_shell_args={'timeout': 60})
    sleep(10)

    # tear down
    unapply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(5)
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 10*******")


@mark.platform_incompatible(['docker'])
def test_replace_acl_when_lag_is_shutdown(configure_lag_l2, topology, step):

    """
    Creating LAG with members, applying ACL, shutting down the lag,
    changing ACL, no shutdown on LAG and sending traffic
    """
    step("*****TEST CASE 11*******")
    step("****test for shutting lag, change acl and no shut lag*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(6)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # shut lag
    config_interface_state(ops2, 'lag', [lag_id_s2], False)

    """
    LAG is in shut state, so no traffic is sent through swithces
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )
    # change acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'udp', 'any',
                    '', 'any', '', '', ""
                )

    # no shut on lag
    config_interface_state(ops2, 'lag', [lag_id_s2], True)

    """
    Configured ACL in switch2 to permit only UDP traffic,
    so only UDP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/UDP',
            filter_str_reverse_udp, 10, True, 'if01'
            )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 11*******")


@mark.platform_incompatible(['docker'])
def test_replace_acl(configure_lag_l2, topology, step):

    """
    Creating LAG with members, applying ACL, changing ACL and sending traffic
    """
    step("*****TEST CASE 12*******")
    step("****test for replace acl*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # change acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'udp', 'any',
                    '', 'any', '', '', ""
                )

    """
    Configured ACL in switch2 to permit only UDP traffic,
    so only UDP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/UDP',
            filter_str_reverse_udp, 10, True, 'if01'
            )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 12*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_acl_on_lag_with_members(configure_lag_l2,
                                                    topology, step):

    """
    Egress
    Creating LAG, adding members, applying ACL to it
    """
    step("*****TEST CASE 13.1*******")
    step("****test for lag with members-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out')

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.1*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_acl_on_lag_with_one_member(configure_lag_l2,
                                                       topology, step):

    """
    Egress
    Creating LAG, adding members, applying ACL to it,
    removing LAG on one member
    """
    step("*****TEST CASE 13.2*******")
    step("****test for no lag on one member-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out')

    # removing one memeber from lag of both the switches
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s1, False)

    # tear down
    teardown_topology(ops1, [interface_list[1]], '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, [interface_list[1]], 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.2*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_acl_on_lag_with_no_member(configure_lag_l2,
                                                      topology, step):

    """
    Egress
    Creating LAG, adding members, applying ACL to it,
    removing LAG on all members
    """
    step("*****TEST CASE 13.3*******")
    step("****test for no lag on all members-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out')

    # removing all members from lag of both the switches
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)

    # tear down
    teardown_topology(ops1, [], '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, [], 'ip', acl_name1, lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.3*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_acl_on_lag_with_shut_on_one_member(
                                        configure_lag_l2, topology, step
                                        ):

    """
    Egress
    Creating LAG, adding members, applying ACL to it,
    shutting down one member from LAG
    """
    step("*****TEST CASE 13.4*******")
    step("****test for shut on some member-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out')

    # shut one member from lag of both the switches
    config_interface_state(ops1, 'port', [interface_list[1]], False)
    config_interface_state(ops2, 'port', [interface_list[1]], False)

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.4*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_acl_on_lag_with_shut_on_all_member(
                                        configure_lag_l2, topology, step
                                        ):

    """
    Egress
    Creating LAG, adding members, applying ACL to it,
    shutting down all members from LAG
    """
    step("*****TEST CASE 13.5*******")
    step("****test for shut on all member-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out')

    # shut all members from lag of both the switches
    config_interface_state(ops1, 'port', interface_list, False)
    config_interface_state(ops2, 'port', interface_list, False)

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.5*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_acl_on_lag_with_shut_on_lag(configure_lag_l2,
                                                        topology, step):

    """
    Egress
    Creating LAG, adding members, applying ACL to it, shutting down the LAG
    """
    step("*****TEST CASE 13.6*******")
    step("****test for shutting lag-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out')

    # shut lag
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    config_interface_state(ops2, 'lag', [lag_id_s2], False)

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.6*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_lag_with_no_member_apply_acl(configure_lag_l2,
                                                         topology, step):

    """
    Egress
    Creating LAG with no member, applying ACL to it
    """
    step("*****TEST CASE 13.7*******")
    step("****test for lag with no members-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    update_lag_members(ops2, interface_list, lag_id_s2, False)

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(
        ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out',
        suppress_warning=True
        )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, [], 'ip', acl_name1, lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.7*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_lag_with_no_members_one_acl_add_member(
                                        configure_lag_l2, topology, step
                                        ):

    """
    Egress
    Creating LAG with no member, applying ACL to it
    """
    step("*****TEST CASE 13.8*******")
    step("****test for lag with no members-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    update_lag_members(ops2, interface_list, lag_id_s2, False)

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(
        ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out',
        suppress_warning=True
        )
    update_lag_members(ops2, interface_list, lag_id_s2, True)

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.8*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_config_persistence(configure_lag_l2,
                                               topology, step):

    """
    Egress
    Creating LAG with members, applying ACL,copy it to startup config
    """
    step("*****TEST CASE 13.9*******")
    step("****test for copy to startup config-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out')

    # copy from running to startup config
    ops2.libs.vtysh.copy_running_config_startup_config(
                                            _shell_args={'timeout': 60}
                                            )
    step("**done copying to startup config**")

    sleep(60)
    print("Rebooting Switch")
    reboot_switch(ops2, shell="vtysh")
    sleep(60)
    step("**reboot completed**")
    sleep(10)
    # tear down
    ops2.libs.vtysh.erase_startup_config(_shell_args={'timeout': 60})
    sleep(10)

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.9*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_replace_acl_when_lag_is_shutdown(
                                        configure_lag_l2, topology, step
                                        ):

    """
    Egress
    Creating LAG with members, applying ACL, shutting down the lag,
    changing ACL, no shutdown on LAG
    """
    step("*****TEST CASE 13.10*******")
    step("****test for shutting lag-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out')

    # shut lag
    config_interface_state(ops2, 'lag', [lag_id_s2], False)

    # change acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'udp', 'any',
                    '', 'any', '', '', ""
                )

    # no shut on lag
    config_interface_state(ops2, 'lag', [lag_id_s2], True)

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.10*******")


@mark.platform_incompatible(['docker'])
def unsupported_test_egress_replace_acl_out(configure_lag_l2, topology, step):

    """
    Egress
    Create LAG with members, apply ACL, change ACL
    """
    step("*****TEST CASE 13.11*******")
    step("****test for replace acl-egress*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'out')

    # change acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'udp', 'any',
                    '', 'any', '', '', ""
                )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 13.11*******")


@mark.platform_incompatible(['docker'])
def unspt_test_lag_members_brought_up_through_pspo_infra_by_removing_from_lag(
                                        configure_lag_l2, topology, step
                                        ):

    """
    1. Creating an ACL(511 entries), applying it to a member,
    Creating LAG with no member, applying ACL, adding member.
    Members are brought down by PSPO Infra
    2. After LAG is removed from the members, members are brought up
    """
    step("*****TEST CASE 14*******")
    step("****test for PSPO Infra up-remove port from LAG*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # create an ACL with 511 entries
    create_acl_with_random_aces(ops2, acl_name2, max_no_of_aces)
    apply_acl(ops2, 'port', 'if01', 'ip', acl_name2, 'in')
    sleep(6)
    """
    LAG has no members, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(
        ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in',
        suppress_warning=True
        )
    sleep(6)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, True)
    sleep(5)

    # checking ovsdb status in hardware
    verify_interface_hw_status(ops2, 1)

    """
    LAG members are broughtdown by PSPO infra, so no traffic is sent
    through the switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    # removing one member from lag of switch2
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, False)
    sleep(5)
    # checking ovsdb status in hardware
    verify_interface_hw_status(ops2, 0)
    # unconfigure 511 entry acl from hardware(switch2)
    unconfigure_acl(ops2, 'ip', acl_name2)
    sleep(5)
    # Adding members to lag of the switch2
    update_lag_members(ops2, interface_list, lag_id_s2, True)

    """
    LAG members are broughtup by PSPO infra, so traffic is sent
    through the switch in both the direction and as ACL permits ingress ICMP
    on switch2, only ICMP traffic is sent from switch1 to switch2
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 14*******")


@mark.platform_incompatible(['docker'])
def unspt_test_lag_members_brought_up_through_pspo_infra_by_removing_acl(
                                        configure_lag_l2, topology, step
                                        ):

    """
    1. Creating an ACL(511 entries), applying it to a member,
    Creating LAG with no member, applying ACL, adding member.
    Members are brought down by PSPO Infra
    2. After ACL is removed from the LAG, members are brought up
    """
    step("*****TEST CASE 15*******")
    step("****test for PSPO Infra down-remove acl from ACL*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # create an ACL with 511 entries
    create_acl_with_random_aces(ops2, acl_name2, max_no_of_aces)
    apply_acl(ops2, 'port', 'if01', 'ip', acl_name2, 'in')
    sleep(6)
    """
    LAG has no members, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(
        ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in',
        suppress_warning=True
        )
    sleep(5)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, True)
    sleep(5)

    # checking ovsdb status in hardware
    verify_interface_hw_status(ops2, 1)

    """
    LAG members are broughtdown by PSPO infra, so no traffic is sent
    through the switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    unapply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(5)
    # checking ovsdb status in hardware
    verify_interface_hw_status(ops2, 0)
    sleep(5)
    """
    LAG members are broughtup by PSPO infra, so traffic is sent
    through the switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )

    # tear down
    unconfigure_acl(ops2, 'ip', acl_name2)
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, [interface_list[0]], '', '',
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 15*******")


@mark.platform_incompatible(['docker'])
def unspt_test_config_persistence_lag_members_are_down_by_pspo_infra(
                                        configure_lag_l2, topology, step
                                        ):

    """
    1. Creating an ACL(511 entries), applying it to a member,
    Creating LAG with no member, applying ACL, adding member.
    Members are brought down by PSPO Infra
    2. Running config is copied to start-up config. Entire LAG is down
    """
    step("*****TEST CASE 16*******")
    step("****test for PSPO Infra down-copy to startup config*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # create an ACL with 511 entries
    create_acl_with_random_aces(ops2, acl_name2, max_no_of_aces)
    apply_acl(ops2, 'port', '4', 'ip', acl_name2, 'in')
    sleep(6)
    """
    LAG has no members, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(
        ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in',
        suppress_warning=True
        )
    sleep(6)
    update_lag_members(ops2, interface_list, lag_id_s2, True)
    sleep(5)

    # checking ovsdb status in hardware
    verify_interface_hw_status(ops2, 2)

    """
    LAG members are broughtdown by PSPO infra, so no traffic is sent
    through the switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False, 'if01'
            )

    # copy from running to startup config
    ops2.libs.vtysh.copy_running_config_startup_config(
                                            _shell_args={'timeout': 60}
                                            )
    step("**done copying to startup config**")

    sleep(60)
    print("Rebooting Switch")
    reboot_switch(ops2, shell="vtysh")
    sleep(60)
    step("**reboot completed**")

    ops2.libs.vtysh.erase_startup_config(_shell_args={'timeout': 60})
    sleep(10)
    # checking ovsdb status in hardware
    verify_interface_hw_status(ops2, 2)

    # removing all memebers from lag switch2
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # checking ovsdb status in hardware
    verify_interface_hw_status(ops2, 0)
    # unconfigure 511 entry acl from hardware(switch2)
    unconfigure_acl(ops2, 'ip', acl_name2)
    # Adding memebers to lag of the switch2
    update_lag_members(ops2, interface_list, lag_id_s2, True)
    """
    LAG members are broughtup by PSPO infra, so traffic is sent
    through the switch in both the direction and as ACL permits ingress ICMP
    on switch2, only ICMP traffic is sent from switch1 to switch2
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)
    step("*****END OF TEST CASE 16*******")


@mark.platform_incompatible(['docker'])
def test_lag_with_no_members_one_acl_add_and_remove_members(
                                        configure_lag_l2, topology, step
                                        ):

    """
    Creating LAG, applying ACL to it, adding members,
    removing members from LAG and sending traffic
    """
    step("*****TEST CASE 17*******")
    step("****test for lag with no members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    update_lag_members(ops2, interface_list, lag_id_s2, False)
    """
    No members are added in LAG, so no traffic is sent through the switches
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(
        ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in',
        suppress_warning=True
        )
    sleep(6)
    update_lag_members(ops2, interface_list, lag_id_s2, True)
    sleep(6)
    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any trafiic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # remove members
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    sleep(5)
    """
    LAG has no members, so no traffic is sent through the
    switch in both the direction
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, [], 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)

    step("*****END OF TEST CASE 17*******")


@mark.platform_incompatible(['docker'])
def test_acl_with_lag_and_delete_lag_and_create_new_lag(
                                        configure_lag_l2, topology, step
                                        ):

    """
    Creating LAG, adding members, applying ACL to it,
    removing LAG and then Creating LAG,
    verifying the absence of old acl on the LAG
    """
    step("*****TEST CASE 18*******")
    step("****test for remove lag and adding lag*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    # Creating LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    """
    Configured LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name1, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name1, 'in')
    sleep(6)

    """
    Configured ACL in switch2 to permit only ICMP traffic,
    so only ICMP traffic is sent from switch1 to switch2 while any traffic can
    be sent from switch2 to switch1
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/TCP',
            filter_str_tcp, 10, False, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )
    config_interface_state(ops2, 'port', interface_list, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    sleep(5)
    config_lag(ops2, lag_id_s2, interface_list, False)
    sleep(5)
    # config new LAG
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    sleep(5)
    """
    Configured new LAG, any traffic can be sent through the switch in
    both the directions
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True, 'if01'
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, True, 'if01'
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True, 'if01'
            )

    # tear down
    teardown_topology(ops1, interface_list, '', '', lag_id_s1, vlan_id_s1)
    teardown_topology(ops2, interface_list, 'ip', acl_name1,
                      lag_id_s2, vlan_id_s2)
    step("*****END OF TEST CASE 18*******")


def teardown_topology(ops, lag_interface_list, acl_type, acl_name,
                      lag_id, vlan_id):
    assert ops is not None

    print('-------TEARDOWN-------')
    # if LAG has members, remove them
    if lag_interface_list:
        update_lag_members(ops, lag_interface_list, lag_id, False)
        sleep(5)

    # if ACL is configured, unconfigure
    if acl_type and acl_name:
        unconfigure_acl(ops, acl_type, acl_name)
        sleep(5)

    # if LAG is configured, remove it
    config_lag(ops, lag_id, enable=False)
    sleep(5)

    # if VLAN is configured, remove it
    config_vlan(ops, vlan_id, enable=False)
    sleep(5)

    # shut down ports
    config_interface_state(ops, 'port', interface_list, False)
    print('-------AFTER TEARDOWN-------')
    time.sleep(5)
