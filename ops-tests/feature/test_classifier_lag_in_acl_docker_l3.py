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
This file tests L3 configuration of ingress ACL applied in LAG,
which runs in docker.

The following tests are in this file-

  Create a lag, Add members to lag, Apply ACL to LAG

  Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
  verify ACL is unapplied to the removed member

  Create a lag, Add members to lag, Apply ACL to lag,
  then delete lag and verify the acl is unapplied to all
  members

  Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
  verify the acl is not applied to removed member, add member back,
  verify acl is applied again

  Create a lag, Add members to lag, Apply ACL to lag, shut 1 member
  verify the acl is not applied to shut member, after enabling the member
  verify acl is applied again

  Create a lag, Add members to lag, Apply ACL to lag, shut lag
  verify the acl is not applied to any member, after enabling
  the lag verify acl is applied again

  Create a lag, Add members to lag, Apply ACL to lag, shut all members
  verify the acl is not applied to any member, after enabling all the members
  verify acl is applied again

  Create a lag, add members and apply ACL to lag,
  shut lag, replace ACL
  no shut lag, the new ACL should be applied in LAG members
"""

from topo_defs import topology_2switch_2host_lag_def
from topo_funcs import topology_2switch_2host_lag
from pytest import fixture
from acl_classifier_common_lib import apply_acl
from acl_classifier_common_lib import unconfigure_acl
from acl_classifier_common_lib import create_n_random_ace_acl
from acl_classifier_common_lib import verify_acl_bindings_applied
from topo_funcs import config_switches_l3_lag
from topo_funcs import config_lag
from topo_funcs import config_interface_state
from topo_funcs import update_lag_members
from topo_funcs import config_hosts_l3
import time
from acl_classifier_common_lib import configure_acl_l3
import pytest


lag_id_s1 = 100
lag_id_s2 = 100
ops1 = None
ops2 = None
no_of_aces = 5
max_aces = 512
acl_name = 'testACL'
interface_list = ['5', '6']
ip_hs1 = '10.10.10.1'
ip_hs2 = '10.10.30.1'
ip_ops1_int1 = '10.10.10.2/24'
ip_ops2_int1 = '10.10.30.2/24'
ip_ops1_lag = '10.10.20.1/24'
ip_ops2_lag = '10.10.20.2/24'
ip_route_ops1 = "ip route 10.10.30.0/24 10.10.20.2"
ip_route_ops2 = "ip route 10.10.10.0/24 10.10.20.1"
ip_route_hs1 = "ip route add default via 10.10.10.2"
ip_route_hs2 = "ip route add default via 10.10.30.2"
TOPOLOGY = topology_2switch_2host_lag_def


def teardown_topology(ops1, ops2):
    for ops in [ops1, ops2]:
        print('-------TEARDOWN-------')
        run = run = ops.libs.vtysh.show_running_config()
        print(run)
        # if ACL is configured, remove it
        if acl_name in run:
            unconfigure_acl(ops, 'ip', acl_name)
        # if LAG is configured, remove it
        if 'lag' in run:
            config_lag(ops, lag_id_s1 if ops == ops1 else lag_id_s2,
                       enable=False)
        # shut down ports
        config_interface_state(ops, 'port', interface_list, False)
        print('-------AFTER TEARDOWN-------')
        time.sleep(5)


def test_create_lag_add_members_apply_acl(topology):
    """
    Create a lag, Add members to lag, Apply ACL to LAG
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces, configure
    #           routes and assign ip address to lag and interface 1
    config_switches_l3_lag(ops1, ops2, ip_ops1_int1, ip_ops2_int1,
                           ip_ops1_lag, ip_ops2_lag, ip_route_ops1,
                           ip_route_ops2, lag_id_s1, lag_id_s2, interface_list)
    # Create ACL
    create_n_random_ace_acl(ops2, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # Verify using the command appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_add_members_apply_acl_remove_one_member(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces, configure
    #           routes and assign ip address to lag and interface 1
    config_switches_l3_lag(ops1, ops2, ip_ops1_int1, ip_ops2_int1,
                           ip_ops1_lag, ip_ops2_lag, ip_route_ops1,
                           ip_route_ops2, lag_id_s1, lag_id_s2, interface_list)
    # Create ACL
    create_n_random_ace_acl(ops2, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # remove a member from LAG
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, False)
    # Verify using the command appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list[1:], 'in')
    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_add_members_apply_acl_delete_lag(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag,
    then delete lag and verify the acl is unapplied to all
    members
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces, configure
    #           routes and assign ip address to lag and interface 1
    config_switches_l3_lag(ops1, ops2, ip_ops1_int1, ip_ops2_int1,
                           ip_ops1_lag, ip_ops2_lag, ip_route_ops1,
                           ip_route_ops2, lag_id_s1, lag_id_s2, interface_list)

    # Create ACL
    create_n_random_ace_acl(ops2, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # delete LAG
    config_lag(ops1, lag_id_s1, enable=False)
    config_lag(ops2, lag_id_s2, enable=False)
    # Verify now no acl entry is applied on any port using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, [], 'in')
    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_apply_acl_add_remove_one_member(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
    verify the acl is not applied to removed member, add member back,
    verify acl is applied again
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces, configure
    #           routes and assign ip address to lag and interface 1
    config_switches_l3_lag(ops1, ops2, ip_ops1_int1, ip_ops2_int1,
                           ip_ops1_lag, ip_ops2_lag, ip_route_ops1,
                           ip_route_ops2, lag_id_s1, lag_id_s2, interface_list)
    # Create ACL
    create_n_random_ace_acl(ops2, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # remove a member from LAG
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, False)
    # Verify now acl entry is applied on all interfaces except the
    # one removed from lag using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list[1:], 'in')
    # add member back to LAG
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, True)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_add_members_apply_acl_shut_one_member(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, shut 1 member
    verify the acl is not applied to shut member, after enabling the member
    verify acl is applied again
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces, configure
    #           routes and assign ip address to lag and interface 1
    config_switches_l3_lag(ops1, ops2, ip_ops1_int1, ip_ops2_int1,
                           ip_ops1_lag, ip_ops2_lag, ip_route_ops1,
                           ip_route_ops2, lag_id_s1, lag_id_s2, interface_list)
    # Create ACL
    create_n_random_ace_acl(ops2, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # shut a member from LAG
    config_interface_state(ops1, 'port', [interface_list[0]], False)
    config_interface_state(ops2, 'port', [interface_list[0]], False)
    # Verify now acl entry is applied on all interfaces except the
    # shut interface using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list[1:], 'in')
    # admin enable the interface again
    config_interface_state(ops1, 'port', [interface_list[0]], True)
    config_interface_state(ops2, 'port', [interface_list[0]], True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_add_members_apply_acl_shut_lag(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, shut lag
    verify the acl is not applied to any member, after enabling
    the lag verify acl is applied again
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces, configure
    #           routes and assign ip address to lag and interface 1
    config_switches_l3_lag(ops1, ops2, ip_ops1_int1, ip_ops2_int1,
                           ip_ops1_lag, ip_ops2_lag, ip_route_ops1,
                           ip_route_ops2, lag_id_s1, lag_id_s2, interface_list)
    # Create ACL
    create_n_random_ace_acl(ops2, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    config_interface_state(ops2, 'lag', [lag_id_s2], False)
    # Verify now acl entry is applied on all interfaces except the
    # shut interface using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, [], 'in')
    # admin enable the interface again
    config_interface_state(ops1, 'lag', [lag_id_s1], True)
    config_interface_state(ops2, 'lag', [lag_id_s2], True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_add_members_apply_acl_shut_all_members(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, shut all members
    verify the acl is not applied to any member, after enabling all the members
    verify acl is applied again
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces, configure
    #           routes and assign ip address to lag and interface 1
    config_switches_l3_lag(ops1, ops2, ip_ops1_int1, ip_ops2_int1,
                           ip_ops1_lag, ip_ops2_lag, ip_route_ops1,
                           ip_route_ops2, lag_id_s1, lag_id_s2, interface_list)
    # Create ACL
    create_n_random_ace_acl(ops2, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # shut all members from LAG
    config_interface_state(ops1, 'port', interface_list, False)
    config_interface_state(ops2, 'port', interface_list, False)
    # Verify now acl entry is applied no interfaces except the
    # shut interface using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, [], 'in')
    # admin enable the interface again
    config_interface_state(ops2, 'port', interface_list, True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_add_members_apply_acl_shut_lag_change_acl(topology):
    """
    Create a lag, add members and apply ACL to lag,
    shut lag, replace ACL
    no shut lag, the new ACL should be applied in LAG members
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces, configure
    #           routes and assign ip address to lag and interface 1
    config_switches_l3_lag(ops1, ops2, ip_ops1_int1, ip_ops2_int1,
                           ip_ops1_lag, ip_ops2_lag, ip_route_ops1,
                           ip_route_ops2, lag_id_s1, lag_id_s2, interface_list)
    # Create ACL
    create_n_random_ace_acl(ops2, acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', acl_name, 'in')
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # Shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    config_interface_state(ops2, 'lag', [lag_id_s1], False)
    # Verify now acl is applied to no interfaces after shutdown
    verify_acl_bindings_applied(ops1, acl_name, [], 'in')
    # Change ACL
    configure_acl_l3(
        ops2, 'ip', acl_name, str(no_of_aces+1), 'permit', 'udp', '10.0.10.1',
        '', '10.0.10.2', '', '')
    # Verify now acl is applied to no interfaces after shutdown
    verify_acl_bindings_applied(ops2, acl_name, [], 'in')
    # No Shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], True)
    config_interface_state(ops2, 'lag', [lag_id_s1], True)
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_acl_bindings_applied(ops2, acl_name, interface_list, 'in')
    # tear down
    teardown_topology(ops1, ops2)
