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
OpenSwitch Test for acl create, delete configuration.
"""

# from pytest import mark
from pytest import fixture
from re import search
# import pytest
# from topology_lib_vtysh import exceptions
import re
from time import sleep
from ipdb import set_trace
from acl_classifier_common_lib import unconfigure_acl
from acl_classifier_common_lib import configure_acl_l3
# from acl_classifier_common_lib import create_and_verify_traffic
# from acl_classifier_common_lib import wait_until_interface_up
from topo_defs import topology_2switch_2host_lag_def
from topo_funcs import config_vlan
from topo_funcs import config_hosts_l2
from topo_funcs import topology_2switch_2host_lag
from acl_classifier_common_lib import interface_up_lag
# from functions import apply_acl_on_lag_in
from acl_classifier_common_lib import check_lag_applied_to_member
# from functions import apply_no_lag_on_interface
from acl_classifier_common_lib import no_shut_interfaces_lag
from acl_classifier_common_lib import create_lag
from acl_classifier_common_lib import add_lag_to_vlan
from acl_classifier_common_lib import apply_members_to_lag
from acl_classifier_common_lib import remove_members_from_lag
from acl_classifier_common_lib import delete_lag
from acl_classifier_common_lib import no_vlan
from acl_classifier_common_lib import apply_acl_on_lag_in
from acl_classifier_common_lib import verify_appctl_acl_applied
from acl_classifier_common_lib import shut_interface
from acl_classifier_common_lib import no_routing_interface


TOPOLOGY = topology_2switch_2host_lag_def

ip_hs1 = '1.1.1.1'
ip_hs2 = '1.1.1.2'
ip_hs1_bitlength = '1.1.1.1/24'
ip_hs2_bitlength = '1.1.1.2/24'
vlan_id_s1 = 10
vlan_id_s2 = 10
lag_id_s1 = 100
lag_id_s2 = 100

ip_hs1_l3 = '1.1.1.1/24'
ip_hs2_l3 = '1.1.3.1/24'
ip_ops1_int1 = '1.1.1.2/24'
ip_ops2_int2 = '1.1.3.2/24'
ip_ops1_lag = '1.1.2.1/24'
ip_ops2_lag = '1.1.2.2/24'
ip_route_ops1 = "ip route 1.1.3.0/24 1.1.2.2"
ip_route_ops2 = "ip route 1.1.1.0/24 1.1.2.1"
ip_route_hs1 = "ip route add default via 1.1.1.2"
ip_route_hs2 = "ip route add default via 1.1.3.2"


@fixture(scope='module')
def configure_lag(topology):
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None

    topology_2switch_2host_lag(ops1, ops2, hs1, hs2)

    no_shut_interfaces_lag(ops1, '1', '5', '6')
    no_routing_interface(ops1, '1')
    no_shut_interfaces_lag(ops2, '1', '5', '6')
    no_routing_interface(ops2, '1')
    config_vlan(ops1, vlan_id_s1)
    config_vlan(ops2, vlan_id_s2)
    config_hosts_l2(hs1, hs2, ip_hs1_bitlength, ip_hs2_bitlength)

    # Wait until interfaces are up
    interface_up_lag(ops1, '1', '5', '6')
    interface_up_lag(ops2, '1', '5', '6')
    set_trace()


# @mark.test_id(10401)
def test_lag_create_add_apply(configure_lag, topology, step):
    """
    Create a lag, Add members to lag, Apply ACL to lag
    """
    acl_name = 'test'
    lag_member1 = '5'
    lag_member2 = '6'

    # On Switch 1
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    """
    1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule
    """
    step('1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule')
    # On Switch 1
    configure_acl_l3(
                    ops1, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )

    # On Switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )
    """
    2. Create a lag, Add members to lag, Apply ACL to lag
    """
    step('2. Create a lag, Add members to lag, Apply ACL to lag')
    create_lag(ops1, lag_id_s1)
    create_lag(ops2, lag_id_s2)

    add_lag_to_vlan(ops1, lag_id_s1, vlan_id_s1)
    add_lag_to_vlan(ops2, lag_id_s2, vlan_id_s2)
    # Add members to LAG
    apply_members_to_lag(ops1, '5', lag_id_s1)
    apply_members_to_lag(ops1, '6', lag_id_s1)
    apply_members_to_lag(ops2, '5', lag_id_s2)
    apply_members_to_lag(ops2, '6', lag_id_s2)

    apply_acl_on_lag_in(ops1, lag_id_s1, acl_name)
    apply_acl_on_lag_in(ops2, lag_id_s2, acl_name)

    """
    2a. Verify if ACL is applied to lag
    """
    step('2a. Verify if ACL is applied to lag')
    run_result = ops1('show run')
    assert search(
       r'(access-list\s+ip\s+test\s+\in)'.format(
                                         **locals()
                                       ), run_result)

    """
    3. Confirm if lag is applied to lag members
    """
    step('3. Confirm if lag is applied to lag members')
    mem1 = ops1.ports[lag_member1]
    mem2 = ops1.ports[lag_member2]
    check_lag_applied_to_member(mem1, lag_id_s1, run_result)
    check_lag_applied_to_member(mem2, lag_id_s1, run_result)

    """
    4. Confirm if ACL applied to lag id
    """
    step('4. Confirm if ACL applied to lag id')
    sleep(5)
    apply_result = ops1('show access-list commands')
    interface_info, rest, *misc = apply_result.split(
                        'apply access-list ip test in'
                                    )
    lag_id_str = 'interface\s+lag{}'.format(lag_id_s1)
    interface_line = re.findall(lag_id_str, interface_info)[-1]
    print('interface_line is {}'.format(interface_line))
    assert(
        str(lag_id_s1) == search(
                '(?<=interface lag)\d+', interface_line).group()
            )

    """
    5. Confirm if ACL applied in hardware
    """
    step('5. Confirm if ACL applied in hardware')
    _shell = ops1.get_shell('bash')
    _shell.send_command(
            'ovs-appctl container/show-acl-bindings')
    appctl_result = _shell.get_response()
    print(appctl_result)
    # confirm if <lag_member1> has <acl_name> <direction>
    port_acl_dir_re = '(\d+)\s+(\S+)\s+(in|out)'
    direction = 'in'

    for line in appctl_result.splitlines():
        port_acl_dir = re.search(port_acl_dir_re, line)
        if port_acl_dir:
            if (port_acl_dir.group(2) == acl_name):
                break
    """
    assert(
        port_acl_dir.group(1) == mem1 and port_acl_dir.group(3) == direction
        )
    """

    """
    6. Clean up configuration
    """
    step('6. Clean up configuration')
    unconfigure_acl(ops1, 'ip', 'test')
    unconfigure_acl(ops2, 'ip', 'test')
    no_vlan(ops1, lag_id_s1, vlan_id_s1)
    no_vlan(ops2, lag_id_s2, vlan_id_s2)
    remove_members_from_lag(ops1, '5', lag_id_s1)
    remove_members_from_lag(ops1, '6', lag_id_s1)
    remove_members_from_lag(ops2, '5', lag_id_s2)
    remove_members_from_lag(ops2, '6', lag_id_s2)
    delete_lag(ops1, lag_id_s1)
    delete_lag(ops2, lag_id_s2)

    run_result = ops1('show run')
    print(run_result)


def test_lag_create_add_apply_remove_1member(configure_lag, topology, step):
    """
    Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
    """
    acl_name = 'test'
    lag_member1 = '5'
    lag_member2 = '6'

    # On Switch 1
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    """
    1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule
    """
    step('1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule')
    # On Switch 1
    configure_acl_l3(
                    ops1, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )

    # On Switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )
    """
    2. Create a lag, Add members to lag, Apply ACL to lag
    """
    step('2. Create a lag, Add members to lag, Apply ACL to lag')
    create_lag(ops1, lag_id_s1)
    create_lag(ops2, lag_id_s2)

    add_lag_to_vlan(ops1, lag_id_s1, vlan_id_s1)
    add_lag_to_vlan(ops2, lag_id_s2, vlan_id_s2)
    # Add members to LAG
    apply_members_to_lag(ops1, '5', lag_id_s1)
    apply_members_to_lag(ops1, '6', lag_id_s1)
    apply_members_to_lag(ops2, '5', lag_id_s2)
    apply_members_to_lag(ops2, '6', lag_id_s2)

    apply_acl_on_lag_in(ops1, lag_id_s1, acl_name)
    # apply_acl_on_lag_in(ops2, lag_id_s2, acl_name)

    """
    2a. Verify if ACL is applied to lag
    """
    step('2a. Verify if ACL is applied to lag')
    run_result = ops1('show run')
    assert search(
       r'(access-list\s+ip\s+test\s+\in)'.format(
                                         **locals()
                                       ), run_result)

    """
    3. Confirm if lag is applied to lag members
    """
    step('3. Confirm if lag is applied to lag members')
    mem1 = ops1.ports[lag_member1]
    mem2 = ops1.ports[lag_member2]
    check_lag_applied_to_member(mem1, lag_id_s1, run_result)
    check_lag_applied_to_member(mem2, lag_id_s1, run_result)

    """
    4. Confirm if ACL applied to lag id
    """
    step('4. Confirm if ACL applied to lag id')
    sleep(5)
    apply_result = ops1('show access-list commands')
    interface_info, rest, *misc = apply_result.split(
                        'apply access-list ip test in'
                                    )
    lag_id_str = 'interface\s+lag{}'.format(lag_id_s1)
    interface_line = re.findall(lag_id_str, interface_info)[-1]
    print('interface_line is {}'.format(interface_line))
    assert(
        str(lag_id_s1) == search(
                '(?<=interface lag)\d+', interface_line).group()
            )

    """
    5. Confirm if ACL applied in hardware
    """
    step('5. Confirm if ACL applied in hardware')
    verify_appctl_acl_applied(ops1, acl_name, lag_member1, 'in', False)

    """
    6. Remove 1 member from LAG and see if ACL still applied
    """
    step('6. Remove 1 member from LAG')
    remove_members_from_lag(ops1, lag_member1, lag_id_s1)
    remove_members_from_lag(ops2, lag_member1, lag_id_s1)

    # verify_appctl_acl_applied(ops1, acl_name, mem2, 'in')
    verify_appctl_acl_applied(ops1, acl_name, 0, 'in', False)

    """
    7. Clean up configuration
    """
    step('7. Clean up configuration')
    unconfigure_acl(ops1, 'ip', 'test')
    unconfigure_acl(ops2, 'ip', 'test')
    no_vlan(ops1, lag_id_s1, vlan_id_s1)
    no_vlan(ops2, lag_id_s2, vlan_id_s2)
    # remove_members_from_lag(ops1, '5', lag_id_s1)
    remove_members_from_lag(ops1, '6', lag_id_s1)
    # remove_members_from_lag(ops2, '5', lag_id_s2)
    remove_members_from_lag(ops2, '6', lag_id_s2)
    delete_lag(ops1, lag_id_s1)
    delete_lag(ops2, lag_id_s2)

    run_result = ops1('show run')
    print(run_result)


def test_lag_create_add_apply_remove_members(configure_lag, topology, step):
    """
    Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
    """
    acl_name = 'test'
    lag_member1 = '5'
    lag_member2 = '6'

    # On Switch 1
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    """
    1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule
    """
    step('1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule')
    # On Switch 1
    configure_acl_l3(
                    ops1, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )

    # On Switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )
    """
    2. Create a lag, Add members to lag, Apply ACL to lag
    """
    step('2. Create a lag, Add members to lag, Apply ACL to lag')
    create_lag(ops1, lag_id_s1)
    create_lag(ops2, lag_id_s2)
    add_lag_to_vlan(ops1, lag_id_s1, vlan_id_s1)
    add_lag_to_vlan(ops2, lag_id_s2, vlan_id_s2)
    # Add members to LAG
    apply_members_to_lag(ops1, '5', lag_id_s1)
    apply_members_to_lag(ops1, '6', lag_id_s1)
    apply_members_to_lag(ops2, '5', lag_id_s2)
    apply_members_to_lag(ops2, '6', lag_id_s2)

    apply_acl_on_lag_in(ops1, lag_id_s1, acl_name)
    # apply_acl_on_lag_in(ops2, lag_id_s2, acl_name)

    """
    2a. Verify if ACL is applied to lag
    """
    step('2a. Verify if ACL is applied to lag')
    run_result = ops1('show run')
    assert search(
       r'(access-list\s+ip\s+test\s+\in)'.format(
                                         **locals()
                                       ), run_result)

    """
    3. Confirm if lag is applied to lag members
    """
    step('3. Confirm if lag is applied to lag members')
    mem1 = ops1.ports[lag_member1]
    mem2 = ops1.ports[lag_member2]
    check_lag_applied_to_member(mem1, lag_id_s1, run_result)
    check_lag_applied_to_member(mem2, lag_id_s1, run_result)

    """
    4. Confirm if ACL applied to lag id
    """
    step('4. Confirm if ACL applied to lag id')
    sleep(5)
    apply_result = ops1('show access-list commands')
    interface_info, rest, *misc = apply_result.split(
                        'apply access-list ip test in'
                                    )
    lag_id_str = 'interface\s+lag{}'.format(lag_id_s1)
    interface_line = re.findall(lag_id_str, interface_info)[-1]
    print('interface_line is {}'.format(interface_line))
    assert(
        str(lag_id_s1) == search(
                '(?<=interface lag)\d+', interface_line).group()
            )

    """
    5. Confirm if ACL applied in hardware
    """
    step('5. Confirm if ACL applied in hardware')
    verify_appctl_acl_applied(ops1, acl_name, 0, 'in', False)

    """
    6. Remove both members from LAG and see if ACL still applied
    """
    step('6. Remove both members from LAG')
    remove_members_from_lag(ops1, lag_member1, lag_id_s1)
    remove_members_from_lag(ops1, lag_member2, lag_id_s1)

    remove_members_from_lag(ops2, lag_member1, lag_id_s2)
    remove_members_from_lag(ops2, lag_member2, lag_id_s2)

    # verify_appctl_acl_applied(ops1, acl_name, mem2, 'in')
    verify_appctl_acl_applied(ops1, acl_name, 0, 'in', False)

    """
    7. Clean up configuration
    """
    step('7. Clean up configuration')
    unconfigure_acl(ops1, 'ip', 'test')
    unconfigure_acl(ops2, 'ip', 'test')
    no_vlan(ops1, lag_id_s1, vlan_id_s1)
    no_vlan(ops2, lag_id_s2, vlan_id_s2)
    # remove_members_from_lag(ops1, '5', lag_id_s1)
    # remove_members_from_lag(ops1, '6', lag_id_s1)
    # remove_members_from_lag(ops2, '5', lag_id_s2)
    # remove_members_from_lag(ops2, '6', lag_id_s2)
    delete_lag(ops1, lag_id_s1)
    delete_lag(ops2, lag_id_s2)

    run_result = ops1('show run')
    print(run_result)


def test_lag_create_add_re_apply_1member(configure_lag, topology, step):
    """
    Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
    """
    acl_name = 'test'
    lag_member1 = '5'
    lag_member2 = '6'

    # On Switch 1
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    """
    1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule
    """
    step('1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule')
    # On Switch 1
    configure_acl_l3(
                    ops1, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )

    # On Switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )
    """
    2. Create a lag, Add members to lag, Apply ACL to lag
    """
    step('2. Create a lag, Add members to lag, Apply ACL to lag')
    create_lag(ops1, lag_id_s1)
    create_lag(ops2, lag_id_s2)

    add_lag_to_vlan(ops1, lag_id_s1, vlan_id_s1)
    add_lag_to_vlan(ops2, lag_id_s2, vlan_id_s2)
    # Add members to LAG
    apply_members_to_lag(ops1, '5', lag_id_s1)
    apply_members_to_lag(ops1, '6', lag_id_s1)
    apply_members_to_lag(ops2, '5', lag_id_s2)
    apply_members_to_lag(ops2, '6', lag_id_s2)

    apply_acl_on_lag_in(ops1, lag_id_s1, acl_name)
    # apply_acl_on_lag_in(ops2, lag_id_s2, acl_name)

    """
    2a. Verify if ACL is applied to lag
    """
    step('2a. Verify if ACL is applied to lag')
    run_result = ops1('show run')
    assert search(
       r'(access-list\s+ip\s+test\s+\in)'.format(
                                         **locals()
                                       ), run_result)

    """
    3. Confirm if lag is applied to lag members
    """
    step('3. Confirm if lag is applied to lag members')
    mem1 = ops1.ports[lag_member1]
    mem2 = ops1.ports[lag_member2]
    check_lag_applied_to_member(mem1, lag_id_s1, run_result)
    check_lag_applied_to_member(mem2, lag_id_s1, run_result)

    """
    4. Confirm if ACL applied to lag id
    """
    step('4. Confirm if ACL applied to lag id')
    sleep(5)
    apply_result = ops1('show access-list commands')
    interface_info, rest, *misc = apply_result.split(
                        'apply access-list ip test in'
                                    )
    lag_id_str = 'interface\s+lag{}'.format(lag_id_s1)
    interface_line = re.findall(lag_id_str, interface_info)[-1]
    print('interface_line is {}'.format(interface_line))
    assert(
        str(lag_id_s1) == search(
                '(?<=interface lag)\d+', interface_line).group()
            )

    """
    5. Confirm if ACL applied in hardware
    """
    step('5. Confirm if ACL applied in hardware')
    verify_appctl_acl_applied(ops1, acl_name, lag_member1, 'in', False)

    """
    6. Remove 1 member from LAG and see if ACL still applied
    """
    step('6. Remove 1 member from LAG')
    remove_members_from_lag(ops1, lag_member1, lag_id_s1)
    remove_members_from_lag(ops2, lag_member1, lag_id_s2)

    # verify_appctl_acl_applied(ops1, acl_name, mem2, 'in')
    verify_appctl_acl_applied(ops1, acl_name, 0, 'in', False)
    run_result = ops1('show run')

    """
    7. Re-add 1 member to LAG and see if ACL still applied
    """
    step('7. Re-Add 1 member to LAG')
    apply_members_to_lag(ops1, lag_member1, lag_id_s1)
    apply_members_to_lag(ops2, lag_member1, lag_id_s2)

    # verify_appctl_acl_applied(ops1, acl_name, mem2, 'in')
    verify_appctl_acl_applied(ops1, acl_name, 0, 'in', False)
    run_result = ops1('show run')

    """
    8. Clean up configuration
    """
    step('8. Clean up configuration')
    unconfigure_acl(ops1, 'ip', 'test')
    unconfigure_acl(ops2, 'ip', 'test')
    no_vlan(ops1, lag_id_s1, vlan_id_s1)
    no_vlan(ops2, lag_id_s2, vlan_id_s2)
    remove_members_from_lag(ops1, '5', lag_id_s1)
    remove_members_from_lag(ops1, '6', lag_id_s1)
    remove_members_from_lag(ops2, '5', lag_id_s2)
    remove_members_from_lag(ops2, '6', lag_id_s2)
    delete_lag(ops1, lag_id_s1)
    delete_lag(ops2, lag_id_s2)

    run_result = ops1('show run')
    print(run_result)


def test_lag_create_add_apply_shut_1member(configure_lag, topology, step):
    """
    Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
    """
    acl_name = 'test'
    lag_member1 = '5'
    lag_member2 = '6'

    # On Switch 1
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert hs1 is not None
    assert hs2 is not None
    """
    1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule
    """
    step('1. Configure an ACL with 1 permit any 1.1.1.1 1.1.1.2 count rule')
    # On Switch 1
    configure_acl_l3(
                    ops1, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )

    # On Switch 2
    configure_acl_l3(
                    ops2, 'ip', acl_name, '1', 'permit', 'any', '1.1.1.1',
                    '', '1.1.1.2', '', 'count', ''
                )
    """
    2. Create a lag, Add members to lag, Apply ACL to lag
    """
    step('2. Create a lag, Add members to lag, Apply ACL to lag')
    create_lag(ops1, lag_id_s1)
    create_lag(ops2, lag_id_s2)
    add_lag_to_vlan(ops1, lag_id_s1, vlan_id_s1)
    add_lag_to_vlan(ops2, lag_id_s2, vlan_id_s2)
    # Add members to LAG
    apply_members_to_lag(ops1, '5', lag_id_s1)
    apply_members_to_lag(ops1, '6', lag_id_s1)
    apply_members_to_lag(ops2, '5', lag_id_s2)
    apply_members_to_lag(ops2, '6', lag_id_s2)

    apply_acl_on_lag_in(ops1, lag_id_s1, acl_name)
    # apply_acl_on_lag_in(ops2, lag_id_s2, acl_name)

    """
    2a. Verify if ACL is applied to lag
    """
    step('2a. Verify if ACL is applied to lag')
    run_result = ops1('show run')
    assert search(
       r'(access-list\s+ip\s+test\s+\in)'.format(
                                         **locals()
                                       ), run_result)

    """
    3. Confirm if lag is applied to lag members
    """
    step('3. Confirm if lag is applied to lag members')
    mem1 = ops1.ports[lag_member1]
    mem2 = ops1.ports[lag_member2]
    check_lag_applied_to_member(mem1, lag_id_s1, run_result)
    check_lag_applied_to_member(mem2, lag_id_s1, run_result)

    """
    4. Confirm if ACL applied to lag id
    """
    step('4. Confirm if ACL applied to lag id')
    sleep(5)
    apply_result = ops1('show access-list commands')
    interface_info, rest, *misc = apply_result.split(
                        'apply access-list ip test in'
                                    )
    lag_id_str = 'interface\s+lag{}'.format(lag_id_s1)
    interface_line = re.findall(lag_id_str, interface_info)[-1]
    print('interface_line is {}'.format(interface_line))
    assert(
        str(lag_id_s1) == search(
                '(?<=interface lag)\d+', interface_line).group()
            )

    """
    5. Confirm if ACL applied in hardware
    """
    step('5. Confirm if ACL applied in hardware')
    verify_appctl_acl_applied(ops1, acl_name, 0, 'in', False)

    """
    6. Shut 1 member in LAG and see if ACL still applied
    """
    step('6. Shut 1 interface in LAG')
    shut_interface(ops1, lag_member1)

    shut_interface(ops2, lag_member1)
    run_result = ops1('show run')
    print(run_result)

    # verify_appctl_acl_applied(ops1, acl_name, mem2, 'in')
    verify_appctl_acl_applied(ops1, acl_name, 0, 'in', False)

    """
    7. Clean up configuration
    """
    step('7. Clean up configuration')
    unconfigure_acl(ops1, 'ip', 'test')
    unconfigure_acl(ops2, 'ip', 'test')
    no_vlan(ops1, lag_id_s1, vlan_id_s1)
    no_vlan(ops2, lag_id_s2, vlan_id_s2)
    no_shut_interfaces_lag(ops1, '1', '5', '6')
    no_shut_interfaces_lag(ops2, '1', '5', '6')
    remove_members_from_lag(ops1, '5', lag_id_s1)
    remove_members_from_lag(ops1, '6', lag_id_s1)
    remove_members_from_lag(ops2, '5', lag_id_s2)
    remove_members_from_lag(ops2, '6', lag_id_s2)
    delete_lag(ops1, lag_id_s1)
    delete_lag(ops2, lag_id_s2)

    run_result = ops1('show run')
    print(run_result)
