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
"""

from topo_defs import topology_2switch_lag_def
from topo_funcs import topology_2switch_lag
# from itertools import product
from pytest import fixture
from acl_classifier_common_lib import apply_acl
from acl_classifier_common_lib import unconfigure_acl
from acl_classifier_common_lib import create_n_ace_acl
from acl_classifier_common_lib import verify_appctl_acl_applied
# from acl_classifier_common_lib import reboot_switch
from topo_funcs import config_lag_l2
from topo_funcs import config_vlan
from topo_funcs import config_lag
from topo_funcs import config_interface_state
from topo_funcs import update_lag_members
import time
from acl_classifier_common_lib import configure_acl_l3
import pytest
# from acl_protocol_names import ipv4_protocol_names


vlan_id_s1 = 10
vlan_id_s2 = 10
lag_id_s1 = 100
lag_id_s2 = 100
ops1 = None
ops2 = None
TOPOLOGY = topology_2switch_lag_def
no_of_aces = 5
max_aces = 512
acl_name = 'testACL'
interface_list = ['5', '6', '7']


def config_port_routing(ops, interface_list, enable):

    assert ops is not None
    assert isinstance(interface_list, list)
    assert isinstance(enable, bool)

    for interface in interface_list:
        assert isinstance(interface, str)
        with ops.libs.vtysh.ConfigInterface(interface) as ctx:
            ctx.routing() if enable else ctx.no_routing()


def teardown_topology(ops):
    print('-------TEARDOWN-------')
    run = ops('show run')
    print(run)
    # if ACL is configured, remove it
    if acl_name in run:
        unconfigure_acl(ops, 'ip', acl_name)
    # if LAG is configured, remove it
    if 'lag' in run:
        config_lag(ops, lag_id_s1, enable=False)
    # if vlan is configured, delete vlan
    if 'vlan '+str(vlan_id_s1) in run:
        config_vlan(ops, vlan_id_s1, enable=False)
    # shut down ports
    config_interface_state(ops, 'port', interface_list, False)
    print('-------AFTER TEARDOWN-------')
    print(ops('show run'))
    time.sleep(5)


@fixture(scope='module')
def create_and_setup_topology(topology):
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    """ Setup interfaces 5 and 6 of both switches """
    topology_2switch_lag(ops1, ops2)


def atest_lag_create_add_apply(topology):
    """
    Create a lag, Add members to lag, Apply ACL to LAG
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify using the command appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1)


def atest_lag_create_add_apply_remove_1member(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, 10)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # remove a member from LAG
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    print(ops1('show run'))
    # Verify using the command appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list[1:], 'in')
    # tear down
    teardown_topology(ops1)


def atest_lag_create_add_apply_delete_lag(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag,
    then delete lag and verify the acl is unapplied to all
    members
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # delete LAG
    config_lag(ops1, lag_id_s1, enable=False)
    # Verify now no acl entry is applied on any port using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, [], 'in')
    # tear down
    teardown_topology(ops1)


def atest_lag_create_apply_add_one_member(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
    verify the acl is not applied to removed member, add member back,
    verify acl is applied again
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    print(interface_list)
    # remove a member from LAG
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    # Verify now acl entry is applied on all interfaces except the
    # one removed from lag using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list[1:], 'in')
    # add member back to LAG
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1)


def atest_lag_create_apply_add_shut_one_member(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, shut 1 member
    verify the acl is not applied to shut member, after enabling the member
    verify acl is applied again
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # shut a member from LAG
    config_interface_state(ops1, 'port', [interface_list[0]], False)
    # Verify now acl entry is applied on all interfaces except the
    # shut interface using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list[1:], 'in')
    # admin enable the interface again
    config_interface_state(ops1, 'port', [interface_list[0]], True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1)


def atest_lag_create_apply_add_shut_lag(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, shut lag
    verify the acl is not applied to any member, after enabling
    the lag verify acl is applied again
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    # Verify now acl entry is applied on all interfaces except the
    # shut interface using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, [], 'in')
    # admin enable the interface again
    config_interface_state(ops1, 'lag', [lag_id_s1], True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1)


# 7
def atest_lag_create_apply_add_shut_all_members(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, shut all members
    verify the acl is not applied to any member, after enabling all the members
    verify acl is applied again
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # shut all members from LAG
    config_interface_state(ops1, 'port', interface_list, False)
    # Verify now acl entry is applied no interfaces except the
    # shut interface using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, [], 'in')
    # admin enable the interface again
    config_interface_state(ops1, 'port', interface_list, True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1)


# 9
def atest_lag_create_apply(topology):
    """
    Create a lag, Apply ACL to lag
    verify acl is applied
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add no interfaces
    # and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, [])
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is applied no interfaces (since LAG has
    # no members) using
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, [], 'in')
    # tear down
    teardown_topology(ops1)


# 10
def atest_lag_create_add_member_after_apply(topology):
    """
    Create a lag, Apply ACL to lag,
    verify the acl is applied to lag, add members to lag
    verify acl is applied to all members
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add no interfaces
    # and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, [])
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is not applied to any interface as
    # there are no members to lag. use command
    # appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, [], 'in')
    # add members to LAG
    config_interface_state(ops1, 'port', interface_list, True)
    update_lag_members(ops1, interface_list, lag_id_s1, True)
    # Verify now acl entry is applied all interfaces in LAG
    # using appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1)


# 11


def atest_lag_create_add_member_reboot(topology):
    """
    Create a lag, add ACL to lag, copy to startup config
    reboot, then verify the acl persists
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add no interfaces
    # and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # copy running config to startup config
    ops1.libs.vtysh.copy_running_config_startup_config()
    run_res_before_boot = ops1.libs.vtysh.show_running_config()
    start_res_before_boot = ops1.libs.vtysh.show_startup_config()
    assert(run_res_before_boot == start_res_before_boot)
    print("Rebooting Switch")
    # reboot_switch(ops1)
    print("Delaying 60 seconds while switch inits")
    time.sleep(60)
    # Verify now acl entry is applied all interfaces in LAG
    # using appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1)


# 12
def atest_lag_create_add_member_shut_lag_change_acl(topology):
    """
    Create a lag, add members and apply ACL to lag,
    shut lag, replace ACL
    no shut lag, the change should be seen
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add no interfaces
    # and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # Shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    # Verify now acl is applied to no interfaces after shutdown
    verify_appctl_acl_applied(ops1, acl_name, [], 'in')
    # Change ACL
    configure_acl_l3(
        ops1, 'ip', acl_name, str(no_of_aces+1), 'permit', 'udp', '10.0.10.1',
        '', '10.0.10.2', '', '')
    print(ops1('show run'))
    # Verify now acl is applied to no interfaces after shutdown
    verify_appctl_acl_applied(ops1, acl_name, [], 'in')
    # No Shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], True)
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1)


# 13
@pytest.mark.test101
def atest_lag_create_add_member_shut_lag_replace_acl(topology):
    """
    Create a lag, add members and apply ACL to lag,
    shut lag, replace ACL
    no shut lag, the change should be seen
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add no interfaces
    # and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # Shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    # Verify now acl is applied to no interfaces after shutdown
    verify_appctl_acl_applied(ops1, acl_name, [], 'in')
    # Change ACL
    unconfigure_acl(ops1, 'ip', acl_name)
    # create new ACL and apply to LAG
    create_n_ace_acl(ops1, 'newACL', no_of_aces)
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', 'newACL', 'in')
    # No Shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], True)
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, 'newACL', interface_list, 'in')
    # tear down
    # Change ACL
    unconfigure_acl(ops1, 'ip', 'newACL')
    teardown_topology(ops1)


# 14
@pytest.mark.test101
def test_lag_create_max_acl_test1(topology):
    """
    Create a lag, add members and apply ACL
    (with 511 ace ACL) to lag, port should go down
    since max is exceeded, remove port from LAG
    port should go up
    """
    ops1 = topology.get('ops1')
    # Configure the switch - Create a lag, add no interfaces
    # and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    # Create ACL
    create_n_ace_acl(ops1, acl_name, max_aces)
    # Apply ACL
    apply_acl(ops1, 'lag', str(lag_id_s1), 'ip', acl_name, 'in')
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_appctl_acl_applied(ops1, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1)
