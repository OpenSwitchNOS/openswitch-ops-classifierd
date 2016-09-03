
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
OpenSwitch Test for LAG with ACLs
"""

from pytest import mark
from topo_defs import topology_2switch_2host_lag_def
from topo_funcs import topology_2switch_2host_lag
from topo_funcs import config_hosts_l2
from pytest import fixture
from topo_funcs import start_scapy_on_hosts
from acl_classifier_common_lib import apply_acl
from acl_classifier_common_lib import create_n_ace_acl
from acl_classifier_common_lib import unconfigure_acl
from acl_classifier_common_lib import reboot_switch
from acl_classifier_common_lib import compare_ovsdb_hw_status_name
from topo_funcs import config_lag
from topo_funcs import config_interface_state
from topo_funcs import update_lag_members
import time
from time import sleep
from topo_funcs import config_switch_lag_l2
from acl_classifier_common_lib import configure_acl_l3
from acl_classifier_common_lib import create_and_verify_traffic

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
ip_hs1 = '10.10.10.1'
ip_hs2 = '10.10.10.2'
ip_hs1_bitlength = '10.10.10.1/24'
ip_hs2_bitlength = '10.10.10.2/24'
vlan_id_s1 = 10
vlan_id_s2 = 10
lag_id_s1 = 100
lag_id_s2 = 100
TOPOLOGY = topology_2switch_2host_lag_def
acl_name = 'testACL'
acl_name2 = 'test_new'
interface_list = ['5', '6']


def config_port_routing(ops, interface_list, enable):

    assert ops is not None
    assert isinstance(interface_list, list)
    assert isinstance(enable, bool)

    for interface in interface_list:
        assert isinstance(interface, str)
        with ops.libs.vtysh.ConfigInterface(interface) as ctx:
            ctx.routing() if enable else ctx.no_routing()


def teardown_topology(ops1, ops2):
    for ops in [ops1, ops2]:
        print('-------TEARDOWN-------')
        run = ops('show run')
        print(run)
        # if ACL is configured, remove it
        if acl_name in run:
            unconfigure_acl(ops, 'ip', acl_name)
            sleep(5)
        # if LAG is configured, remove it
        if 'lag' in run:
            config_lag(ops, lag_id_s1, enable=False)
            sleep(5)
        # shut down ports
        config_interface_state(ops, 'port', interface_list, False)
        sleep(5)
        print('-------AFTER TEARDOWN-------')
        print(ops('show run'))
        time.sleep(5)


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
def test_lag_with_members(configure_lag_l2, topology, step):

    """
    create LAG, adding members, applying ACL to it and sending traffic
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)


@mark.platform_incompatible(['docker'])
def test_no_lag_on_one_member(configure_lag_l2, topology, step):

    """
    create LAG, adding members, applying ACL to it,
    remove LAG on one member and sending traffic
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # removing one memeber from lag of both the switches
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, False)

    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # tear down
    update_lag_members(ops1, [interface_list[1]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[1]], lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 2*******")


@mark.platform_incompatible(['docker'])
def test_no_lag_on_all_members(configure_lag_l2, topology, step):

    """
    create LAG, adding members, applying ACL to it,
    remove LAG on all members and sending traffic
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """

    # removing all memebers from lag of both the switches
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)

    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )
    # tear down
    teardown_topology(ops1, ops2)
    step("*****END OF TEST CASE 3*******")


@mark.platform_incompatible(['docker'])
def test_shut_some_member(configure_lag_l2, topology, step):

    """
    create LAG, adding members, applying ACL to it,
    shutdown one member from LAG and sending traffic
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # shut one memeber from lag of both the switches
    config_interface_state(ops1, 'port', [interface_list[1]], False)
    config_interface_state(ops2, 'port', [interface_list[1]], False)

    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )

    # tear down
    config_interface_state(ops1, 'port', [interface_list[0]], False)
    config_interface_state(ops2, 'port', [interface_list[0]], False)
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 4*******")


@mark.platform_incompatible(['docker'])
def test_shut_all_member(configure_lag_l2, topology, step):

    """
    create LAG, adding members, applying ACL to it,
    shutdown all members from LAG and sending traffic
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # shut all memebers from lag of both the switches
    config_interface_state(ops1, 'port', interface_list, False)
    config_interface_state(ops2, 'port', interface_list, False)

    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 5*******")


@mark.platform_incompatible(['docker'])
def test_shut_lag(configure_lag_l2, topology, step):

    """
    create LAG, adding members, applying ACL to it,
    shutdown the LAG and sending traffic
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # shut lag
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    config_interface_state(ops2, 'lag', [lag_id_s2], False)

    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 6*******")


@mark.platform_incompatible(['docker'])
def test_lag_with_no_members(configure_lag_l2, topology, step):

    """
    create LAG with no member, applying ACL to it and sending traffic
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 7*******")


@mark.platform_incompatible(['docker'])
def test_lag_with_no_members_one_acl(configure_lag_l2, topology, step):

    """
    create LAG with no member, applying ACL,
    add member to it and sending traffic
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    update_lag_members(ops2, interface_list, lag_id_s2, True)
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 8*******")


@mark.platform_incompatible(['docker'])
def test_pspo_infra_down(configure_lag_l2, topology, step):

    """
    Create an ACL(511 entries), apply it to a member,
    create LAG with no member, applying ACL, add member.
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
    # create an ACL with 511 entries
    create_n_ace_acl(ops2, acl_name2, 511)
    apply_acl(ops2, 'port', '4', 'ip', acl_name2, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, True)

    # checking ovsdb status in hardware
    # compare_ovsdb_hw_status_name(ops2, 1)
    step("*****TEST CASE 9.2*******")
    # creating and verifying traffic

    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    """

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, False)
    unconfigure_acl(ops2, 'ip', acl_name2)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 9*******")


@mark.platform_incompatible(['docker'])
def test_lag_acl_copy_to_startup_config(configure_lag_l2, topology, step):

    """
    Create LAG with members, applying ACL,
    copy it to startup config and send traffic
    """
    step("*****TEST CASE 10*******")
    step("****test for lag with members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
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
    ops2('show run')
    # tear down
    ops2.libs.vtysh.erase_startup_config(_shell_args={'timeout': 60})

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 10*******")


@mark.platform_incompatible(['docker'])
def test_shut_lag_change_acl_no_shut_lag(configure_lag_l2, topology, step):

    """
    Create LAG with members, applying ACL,shutdown the lag,
    change ACL, no shutdown on LAG and send traffic
    """
    step("*****TEST CASE 11*******")
    step("****test for shutting lag*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # shut lag
    config_interface_state(ops2, 'lag', [lag_id_s2], False)

    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # change acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'udp', 'any',
                    '', 'any', '', '', ""
                )

    # no shut on lag
    config_interface_state(ops2, 'lag', [lag_id_s2], True)

    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/UDP',
            filter_str_reverse, 10, True
            )
    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 11*******")


@mark.platform_incompatible(['docker'])
def test_replace_acl(configure_lag_l2, topology, step):

    """
    Create LAG with members, apply ACL, change ACL and send traffic
    """
    step("*****TEST CASE 12*******")
    step("****test for shutting lag*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """

    # change acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'udp', 'any',
                    '', 'any', '', '', ""
                )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/UDP',
            filter_str_reverse, 10, True
            )
    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 12*******")


@mark.platform_incompatible(['docker'])
def test_lag_with_members_out(configure_lag_l2, topology, step):

    """
    Egress
    create LAG, adding members, applying ACL to it
    """
    step("*****TEST CASE 13.1*******")
    step("****test for lag with members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)
    step("*****END OF TEST CASE 13.1*******")


@mark.platform_incompatible(['docker'])
def test_no_lag_on_one_member_out(configure_lag_l2, topology, step):

    """
    Egress
    create LAG, adding members, applying ACL to it,
    remove LAG on one member
    """
    step("*****TEST CASE 13.2*******")
    step("****test for no lag on one member*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # removing one memeber from lag of both the switches
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s1, False)

    # tear down
    update_lag_members(ops1, [interface_list[1]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[1]], lag_id_s1, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 13.2*******")


@mark.platform_incompatible(['docker'])
def test_no_lag_on_all_members_out(configure_lag_l2, topology, step):

    """
    Egress
    create LAG, adding members, applying ACL to it,
    remove LAG on all members
    """
    step("*****TEST CASE 13.3*******")
    step("****test for no lag on all members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """

    # removing all memebers from lag of both the switches
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)

    # tear down
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 13.3*******")


@mark.platform_incompatible(['docker'])
def test_shut_some_member_out(configure_lag_l2, topology, step):

    """
    Egress
    create LAG, adding members, applying ACL to it,
    shutdown one member from LAG
    """
    step("*****TEST CASE 13.4*******")
    step("****test for shut on some member*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # shut one memeber from lag of both the switches
    config_interface_state(ops1, 'port', [interface_list[1]], False)
    config_interface_state(ops2, 'port', [interface_list[1]], False)

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)
    step("*****END OF TEST CASE 13.4*******")


@mark.platform_incompatible(['docker'])
def test_shut_all_member_out(configure_lag_l2, topology, step):

    """
    Egress
    create LAG, adding members, applying ACL to it,
    shutdown all members from LAG
    """
    step("*****TEST CASE 13.5*******")
    step("****test for shut on all member*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # shut all memebers from lag of both the switches
    config_interface_state(ops1, 'port', interface_list, False)
    config_interface_state(ops2, 'port', interface_list, False)

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)
    step("*****END OF TEST CASE 13.5*******")


@mark.platform_incompatible(['docker'])
def test_shut_lag_out(configure_lag_l2, topology, step):

    """
    Egress
    create LAG, adding members, applying ACL to it, shutdown the LAG
    """
    step("*****TEST CASE 13.6*******")
    step("****test for shutting lag*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # shut lag
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    config_interface_state(ops2, 'lag', [lag_id_s2], False)

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)
    step("*****END OF TEST CASE 13.6*******")


@mark.platform_incompatible(['docker'])
def test_lag_with_no_members_out(configure_lag_l2, topology, step):

    """
    Egress
    create LAG with no member, applying ACL to it
    """
    step("*****TEST CASE 13.7*******")
    step("****test for lag with no members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    update_lag_members(ops2, interface_list, lag_id_s2, False)

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 13.7*******")


@mark.platform_incompatible(['docker'])
def test_lag_with_no_members_one_acl_out(configure_lag_l2, topology, step):

    """
    Egress
    create LAG with no member, applying ACL to it
    """
    step("*****TEST CASE 13.8*******")
    step("****test for lag with no members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    update_lag_members(ops2, interface_list, lag_id_s2, False)

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    update_lag_members(ops2, interface_list, lag_id_s2, True)

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 13.8*******")


@mark.platform_incompatible(['docker'])
def test_lag_acl_cpy_to_startup_conf_out(configure_lag_l2, topology, step):

    """
    Egress
    Create LAG with members, applying ACL,copy it to startup config
    """
    step("*****TEST CASE 13.10*******")
    step("****test for lag with members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """

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
    ops2('show run')
    # tear down
    ops2.libs.vtysh.erase_startup_config(_shell_args={'timeout': 60})

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)
    step("*****END OF TEST CASE 13.10*******")


@mark.platform_incompatible(['docker'])
def test_change_acl_no_shut_lag_out(configure_lag_l2, topology, step):

    """
    Egress
    Create LAG with members, applying ACL,shutdown the lag,
    change ACL, no shutdown on LAG
    """
    step("*****TEST CASE 13.11*******")
    step("****test for shutting lag*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # shut lag
    config_interface_state(ops2, 'lag', [lag_id_s2], False)

    # change acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'udp', 'any',
                    '', 'any', '', '', ""
                )

    # no shut on lag
    config_interface_state(ops2, 'lag', [lag_id_s2], True)
    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 13.11*******")


@mark.platform_incompatible(['docker'])
def test_replace_acl_out(configure_lag_l2, topology, step):

    """
    Egress
    Create LAG with members, apply ACL, change ACL
    """
    step("*****TEST CASE 13.12*******")
    step("****test for shutting lag*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'out')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+out'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """

    # change acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'udp', 'any',
                    '', 'any', '', '', ""
                )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 13.12*******")


@mark.platform_incompatible(['docker'])
def test_pspo_infra_up_lag(configure_lag_l2, topology, step):

    """
    1. Create an ACL(511 entries), apply it to a member,
    create LAG with no member, applying ACL, add member.
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
    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # create an ACL with 511 entries
    create_n_ace_acl(ops2, acl_name2, 511)
    apply_acl(ops2, 'port', '4', 'ip', acl_name2, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, True)

    # checking ovsdb status in hardware
    # compare_ovsdb_hw_status_name(ops2, 1)

    step("*****TEST CASE 9.2*******")
    # creating and verifying traffic

    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    """
    step("*****TEST CASE 14.2*******")
    # removing all memebers from lag of both the switches
    update_lag_members(ops2, [interface_list[0]], lag_id_s1, False)
    # checking ovsdb status in hardware
    # compare_ovsdb_hw_status_name(ops2, 0)

    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    """
    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    unconfigure_acl(ops2, 'ip', acl_name2)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 14*******")


@mark.platform_incompatible(['docker'])
def test_pspo_infra_up_acl(configure_lag_l2, topology, step):

    """
    1. Create an ACL(511 entries), apply it to a member,
    create LAG with no member, applying ACL, add member.
    Members are brought down by PSPO Infra
    2. After ACL is removed from the LAG, members are brought up
    """
    step("*****TEST CASE 15*******")
    step("****test for PSPO Infra down-remove acl from LAG*****")

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
    create_n_ace_acl(ops2, acl_name2, 511)
    apply_acl(ops2, 'port', '4', 'ip', acl_name2, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, True)

    # checking ovsdb status in hardware
    # compare_ovsdb_hw_status_name(ops2, 1)

    step("*****TEST CASE 9.2*******")
    # creating and verifying traffic

    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    """
    unconfigure_acl(ops2, 'ip', acl_name)
    # checking ovsdb status in hardware
    # compare_ovsdb_hw_status_name(ops2, 0)

    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    """
    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, False)
    unconfigure_acl(ops2, 'ip', acl_name2)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 15*******")


@mark.platform_incompatible(['docker'])
def test_pspo_infra_down_startup_config(configure_lag_l2, topology, step):

    """
    1. Create an ACL(511 entries), apply it to a member,
    create LAG with no member, applying ACL, add member.
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
    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # create an ACL with 511 entries
    create_n_ace_acl(ops2, acl_name2, 511)
    apply_acl(ops2, 'port', '4', 'ip', acl_name2, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    update_lag_members(ops2, interface_list, lag_id_s2, True)

    # checking ovsdb status in hardware
    compare_ovsdb_hw_status_name(ops2, 2)

    # creating and verifying traffic
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    """
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
    ops2('show run')
    # tear down
    ops2.libs.vtysh.erase_startup_config(_shell_args={'timeout': 60})
    # checking ovsdb status in hardware
    # compare_ovsdb_hw_status_name(ops2, 2)

    # removing all memebers from lag of both the switches
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # checking ovsdb status in hardware
    # compare_ovsdb_hw_status_name(ops2, 0)

    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    unconfigure_acl(ops2, 'ip', acl_name2)
    teardown_topology(ops1, ops2)
    step("*****END OF TEST CASE 16*******")


@mark.platform_incompatible(['docker'])
def test_lag_no_mmbrs_one_acl_add_remove(configure_lag_l2, topology, step):

    """
    create LAG, applying ACL to it, adding members,
    remove memberd from LAG and sending traffic
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

    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, False
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    update_lag_members(ops2, interface_list, lag_id_s2, True)
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, False
            )
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # remove members
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str_udp, 10, False
            )
    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 17*******")


@mark.platform_incompatible(['docker'])
def test_remove_one_member(configure_lag_l2, topology, step):

    """
    create LAG, adding members, applying ACL to it,
    remove LAG on one member and sending traffic
    """
    step("*****TEST CASE 18*******")
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # removing one memeber from lag of both the switches
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, False)

    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # tear down
    update_lag_members(ops1, [interface_list[1]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[1]], lag_id_s2, False)
    teardown_topology(ops1, ops2)

    step("*****END OF TEST CASE 18*******")


@mark.platform_incompatible(['docker'])
def test_remove_all_member(configure_lag_l2, topology, step):

    """
    create LAG, adding members, applying ACL to it,
    remove LAG on all member and sending traffic
    """
    step("*****TEST CASE 19*******")
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
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """

    # removing all memebers from lag of both the switches
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)

    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, False
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, False
            )
    # tear down
    teardown_topology(ops1, ops2)
    step("*****END OF TEST CASE 19*******")


@mark.platform_incompatible(['docker'])
def test_acl_no_lag_add_lag_verify_acl(configure_lag_l2, topology, step):

    """
    create LAG, adding members, applying ACL to it,
    remove LAG and then create LAG,
    verify the absence of old acl on the LAG
    """
    step("*****TEST CASE 20*******")
    step("****test for lag with members*****")

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    # Create LAG, add members to the LAG
    config_switch_lag_l2(
                        ops1, ops2, vlan_id_s1, vlan_id_s2,
                        lag_id_s1, lag_id_s2
                        )

    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_hs2,
            '', ip_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    # configure acl on switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '10', 'permit', 'icmp', 'any',
                    '', 'any', '', '', ""
                )

    # apply acl on lag for switch 2
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # verify
    """
    show_interface_lag = ops2.libs.vtysh.show_access_list_commands(
                                            'interface lag'+str(lag_id_s2))
    assert search(
        ""
        r'apply\s+access-list\s+ip\s'+acl_name+'\s+in'.format(
                                                        **locals()
                                                    ), show_interface_lag
    )
    """
    # creating and verifying traffic
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    create_and_verify_traffic(
            topology, hs1, hs2, ip_hs1,
            '', ip_hs2, '', 'IP/UDP',
            filter_str, 10, False
            )
    config_interface_state(ops2, 'port', interface_list, False)
    config_lag(ops2, lag_id_s2, interface_list, False)
    config_lag(ops2, lag_id_s2, interface_list, True)
    """
    create_and_verify_traffic(
            topology, hs1, hs2, ip_only_hs1,
            '', ip_only_hs2, '', 'IP/ICMP',
            filter_str, 10, True
            )
    # reverse traffic
    create_and_verify_traffic(
            topology, hs2, hs1, ip_only_hs2,
            '', ip_only_hs1, '', 'IP/ICMP',
            filter_str_reverse, 10, True
            )
    """
    # tear down
    update_lag_members(ops1, interface_list, lag_id_s1, False)
    update_lag_members(ops2, interface_list, lag_id_s2, False)
    teardown_topology(ops1, ops2)
    step("*****END OF TEST CASE 20*******")
