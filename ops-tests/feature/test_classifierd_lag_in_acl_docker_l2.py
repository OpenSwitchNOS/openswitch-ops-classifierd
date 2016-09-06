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
This file tests L2 configuration of ingress ACL applied in LAG,
which runs in docker.
The following tests are in this file-

1 Create a lag, Add members to lag, Apply ACL to LAG

2 Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
  verify ACL is unapplied to the removed member

3 Create a lag, Add members to lag, Apply ACL to lag,
  then delete lag and verify the acl is unapplied to all
  members

4 Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
  verify the acl is not applied to removed member, add member back,
  verify acl is applied again

5 Create a lag, Add members to lag, Apply ACL to lag, shut 1 member
  verify the acl is not applied to shut member, after enabling the member
  verify acl is applied again

6 Create a lag, Add members to lag, Apply ACL to lag, shut lag
  verify the acl is not applied to any member, after enabling
  the lag verify acl is applied again

7 Create a lag, Add members to lag, Apply ACL to lag, shut all members
  verify the acl is not applied to any member, after enabling all the members
  verify acl is applied again

8 Create a lag, add members and apply ACL to lag,
  shut lag, replace ACL
  no shut lag, the new ACL should be applied in LAG members

9 Create a lag, apply ACL to lag verify ACL is not applied since lag has
  no members, add members, verify ACL is applied to all members.

10 Apply ACL with 512 ACEs to a port, Create a lag, Add members to lag,
   Apply ACL to lag, verify the acl is not applied to lag and members
   are down

11 Create a lag, add members, apply ingress ACL, apply egress ACL, verfiy
   ACL is applied in both directions, add a new member to lag, verify
   none of the ACLs is applied to new lag member
"""

from acl_classifier_common_lib import apply_acl
from acl_classifier_common_lib import unconfigure_acl
from acl_classifier_common_lib import create_acl_with_random_aces
from acl_classifier_common_lib import verify_interface_hw_status
from acl_classifier_common_lib import verify_acl_bindings
from acl_classifier_common_lib import configure_acl_l3
from topo_funcs import config_lag_l2
from topo_funcs import config_vlan
from topo_funcs import config_lag
from topo_funcs import config_interface_state
from topo_funcs import update_lag_members
import time


vlan_id_s1 = 10
vlan_id_s2 = 10
lag_id_s1 = 100
lag_id_s2 = 100
port_id_s2 = 'if01'
ops1 = None
ops2 = None
no_of_aces = 5
max_no_of_aces = 512
test_acl_name = 'testACL'
max_test_acl_name = 'maxtestACL'
rollback_test_acl_name = 'rollbackACL'
interface_list = ['if05', 'if06']

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


def teardown_topology(ops1, ops2):
    assert ops1 is not None
    assert ops2 is not None
    for ops in [ops1, ops2]:
        print('-------TEARDOWN-------')
        run = ops.libs.vtysh.show_running_config()
        # if ACL is configured, remove it
        if run['access-list']['ip']:
            for acl in run['access-list']['ip'].keys():
                unconfigure_acl(ops, 'ip', acl)
        # if LAG is configured, remove it
        if 'lag' in run['interface']:
            config_lag(ops, lag_id_s1 if ops == ops1 else lag_id_s2,
                       enable=False)
        if str(vlan_id_s1 if ops == ops1 else vlan_id_s2) in run['vlan']:
            config_vlan(ops, vlan_id_s1 if ops == ops1 else vlan_id_s2,
                        enable=False)
        # shut down ports
        config_interface_state(ops, 'port', interface_list, False)
        print('-------AFTER TEARDOWN-------')
        run = ops.libs.vtysh.show_running_config()
        print(run)
        time.sleep(5)


def test_create_lag_add_members_apply_acl(topology):
    """
    Create a lag, Add members to lag, Apply ACL to LAG
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in')
    # Verify using the command appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')

    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_add_members_apply_acl_remove_one_member(topology):
    """
    Create a lag, Add members to lag, Apply ACL to lag, Remove 1 member
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, 10)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in')
    # remove a member from LAG
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, False)
    # Verify using the command appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list[1:], 'in')

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
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in')
    # delete LAG
    config_lag(ops1, lag_id_s1, enable=False)
    config_lag(ops2, lag_id_s2, enable=False)
    # Verify now no acl entry is applied on any port using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, [], 'in')

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
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')
    print(interface_list)
    # remove a member from LAG
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, False)
    update_lag_members(ops2, [interface_list[0]], lag_id_s1, False)
    # Verify now acl entry is applied on all interfaces except the
    # one removed from lag using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list[1:], 'in')
    # add member back to LAG
    update_lag_members(ops1, [interface_list[0]], lag_id_s1, True)
    update_lag_members(ops2, [interface_list[0]], lag_id_s2, True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')

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
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')
    # shut a member from LAG
    config_interface_state(ops1, 'port', [interface_list[0]], False)
    config_interface_state(ops2, 'port', [interface_list[0]], False)
    # Verify now acl entry is applied on all interfaces except the
    # shut interface using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list[1:], 'in')
    # admin enable the interface again
    config_interface_state(ops1, 'port', [interface_list[0]], True)
    config_interface_state(ops2, 'port', [interface_list[0]], True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')

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
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')
    # shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    config_interface_state(ops2, 'lag', [lag_id_s2], False)
    # Verify now acl entry is applied on all interfaces except the
    # shut interface using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, [], 'in')
    # admin enable the interface again
    config_interface_state(ops1, 'lag', [lag_id_s1], True)
    config_interface_state(ops2, 'lag', [lag_id_s2], True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')

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
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in')
    # Verify now acl entry is applied all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')
    # shut all members from LAG
    config_interface_state(ops1, 'port', interface_list, False)
    config_interface_state(ops2, 'port', interface_list, False)
    # Verify now acl entry is applied no interfaces except the
    # shut interface using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, [], 'in')
    # admin enable the interface again
    config_interface_state(ops1, 'port', interface_list, True)
    config_interface_state(ops2, 'port', interface_list, True)
    # Verify now acl entry is applied on all interfaces using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')

    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_add_members_apply_acl_shut_lag_replace_acl(topology):
    """
    Create a lag, add members and apply ACL to lag,
    shut lag, replace ACL
    no shut lag, the new ACL should be applied in LAG members
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add no interfaces
    # and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in')
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')
    # Shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], False)
    config_interface_state(ops2, 'lag', [lag_id_s2], False)
    # Verify now acl is applied to no interfaces after shutdown
    verify_acl_bindings(ops2, test_acl_name, [], 'in')
    # Change ACL
    configure_acl_l3(
        ops2, 'ip', test_acl_name, str(no_of_aces+1), 'permit',
        'udp', '10.0.10.1', '', '10.0.10.2', '', '')
    # Verify now acl is applied to no interfaces after shutdown
    verify_acl_bindings(ops2, test_acl_name, [], 'in')
    # No Shut LAG
    config_interface_state(ops1, 'lag', [lag_id_s1], True)
    config_interface_state(ops2, 'lag', [lag_id_s2], True)
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in')

    # tear down
    teardown_topology(ops1, ops2)


def test_create_lag_apply_acl_add_members(topology):
    """
    Create a lag, apply ACL to lag verify ACL is not applied since lag has
    no members, add members, verify ACL is applied to all members.
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add no interfaces
    # and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, [])
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, [])
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces,
                                suppress_warning=True)
    # Apply ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in',
              suppress_warning=True)
    # Verify now acl entry is applied to lag interfaces
    # Use command appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, [], 'in')
    # Add members to LAG
    update_lag_members(ops1, interface_list, lag_id_s1, True)
    update_lag_members(ops2, interface_list, lag_id_s2, True)
    # Verify now acl is applied to all members in LAG
    print(ops2('show run'))
    verify_acl_bindings(ops2, test_acl_name, interface_list, 'in',
                        retries=6)
    # tear down
    teardown_topology(ops1, ops2)


def test_lag_members_down_with_pspo(topology):
    """
    Create an ACL with 511 ACEs, apply to a port, Create a lag, add members,
    apply ACL, verify lag members are down.
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Create ACL
    create_acl_with_random_aces(ops2, max_test_acl_name, max_no_of_aces)
    # Apply ACL to a port
    apply_acl(ops2, 'port', port_id_s2, 'ip', max_test_acl_name, 'in')
    # Verify acl is applied to port
    # use command appctl container/show-acl-bindings
    verify_acl_bindings(ops2, max_test_acl_name, [port_id_s2], 'in', True)
    # Configure the switch - Create a lag, add interfaces and add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, interface_list)
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, interface_list)
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces)
    # Apply ACL to lag
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in',
              suppress_warning=True)
    # Verify hw_status for two lag interfaces in Interface table
    verify_interface_hw_status(ops2, 2, interface_list)

    # tear down
    teardown_topology(ops1, ops2)


def test_acl_rollback_on_lag_member(topology):
    """
    Create a lag, add members, apply ingress ACL, apply egress ACL,
    verify ACL is applied in both directions,
    Add a new member to lag, verify ACL is not applied to the new
    lag member
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    # Configure the switch - Create a lag, add one interface and
    # add lag to vlan
    config_lag_l2(ops1, vlan_id_s1, lag_id_s1, [interface_list[0]])
    config_lag_l2(ops2, vlan_id_s2, lag_id_s2, [interface_list[0]])
    # Create ACL
    create_acl_with_random_aces(ops2, test_acl_name, no_of_aces)
    # Create ACL
    create_acl_with_random_aces(ops2, rollback_test_acl_name, no_of_aces)
    # Apply ingress ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', test_acl_name, 'in')
    # print(ops2('show run'))
    # Apply egress ACL
    apply_acl(ops2, 'lag', str(lag_id_s2), 'ip', rollback_test_acl_name, 'out')
    print(ops2('show run'))
    # Verify now acl entry is applied to lag using
    # appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, [interface_list[0]], 'in', True)
    verify_acl_bindings(ops2, rollback_test_acl_name, [interface_list[0]],
                        'out', True)
    # Add a member to LAG
    update_lag_members(ops1, [interface_list[1]], lag_id_s1, True)
    update_lag_members(ops2, [interface_list[1]], lag_id_s1, True)
    # Verify now acl entry is not applied to interface that was
    # added to the lag using appctl container/show-acl-bindings
    verify_acl_bindings(ops2, test_acl_name, [interface_list[1]], 'in', False)
    verify_acl_bindings(ops2, rollback_test_acl_name, [interface_list[1]],
                        'out', False)

    # tear down
    teardown_topology(ops1, ops2)
