# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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

from pytest import mark
from re import search
from ipdb import set_trace
import pytest
from topology_lib_vtysh.exceptions import UnknownCommandException
# from topology_lib_vtysh.exceptions import IncompleteCommandException
# from topology_lib_vtysh.exceptions import PermittedException
# from topology_lib_vtysh.exceptions import AclEmptyException
# from topology_lib_vtysh.exceptions import InvalidQnCommandException
from topology_lib_vtysh.exceptions import AclDoesNotExistException
from topology_lib_vtysh.exceptions import EchoCommandException
from topology_lib_vtysh.exceptions import TcamResourcesException
from topology_lib_vtysh.exceptions import ResequenceNumberException
# from topology_lib_vtysh.exceptions import AceDoesNotExistException
# from topology_lib_vtysh.exceptions import AmbiguousCommandException
from topology_lib_vtysh.exceptions import InvalidL4SourcePortRangeException

TOPOLOGY = """
# +--------+
# |  ops1  |
# +--------+

# Nodes
[image="fs-genericx86-64:latest" \
type=openswitch name="OpenSwitch 1"] ops1
# [type=openswitch name="OpenSwitch 1"] ops1

# Links
"""


@mark.test_id(10402)
def test_ace_create_delete(topology, step):
    """
    Test the creation and deleteion of access control list.

    Build a topology of one switch. Tested the ability to properly add ACL,
    delete ACL.
    """
    ops1 = topology.get('ops1')

    assert ops1 is not None

    # Create ACL with valid name

    # Configure create an **acl** on switch with valid name.
    # Run commands
    # root# config terminal
    """
    ops1('config terminal')

    # root(config)# access-list ip test1
    ops1('access-list ip test1')
    # VM with ops1.libs.vtysh.Configure() as ctx:
    #    ctx.access_list_ip('test1')
    """
    step('################ T1 Add Permit ACE ###########')
    step('################ to existing ACL ###############')

    # set_trace()

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.permit('', '1', 'pim', '1.2.3.4', '', '5.6.7.8', '')
    # The **acl** must be present in switch configuration.
    # Run commands
    # root(config-acl)# exit

    # ops1('exit')
    # ops1('exit')

    # root# show run

    test1_result = ops1('show run')

    # test1_result = ops1('show run')

    # Test pass criteria
    # VM string test : access-list ip test1
    # Verify acl presents after created.
    assert search(
       ''
       r'1\s+permit\s+pim\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'
       '\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'.format(
                                         **locals()
                                       ), test1_result
    )
    step('################ T2 Add Deny ACE ###########')
    step('################ to existing ACL ###############')

    # set_trace()

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.deny('', '1', 'igmp', '1.2.3.4', '', '5.6.7.8', '')
    # The **acl** must be present in switch configuration.
    # Run commands
    # root(config-acl)# exit

    # ops1('exit')
    # ops1('exit')

    # root# show run

    test1_result = ops1('show run')

    # test1_result = ops1('show run')

    # Test pass criteria
    # VM string test : access-list ip test1
    # Verify acl presents after created.
    assert search(
       ''
       r'1\s+deny\s+igmp\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'
       '\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'.format(
                                         **locals()
                                       ), test1_result
    )

    step('################ T3 Remove ACE ###########')
    step('################ from existing ACL ###############')
    # set_trace()

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.no('1')
    # The **acl** must be present in switch configuration.
    # Run commands
    # root(config-acl)# exit

    # ops1('exit')
    # ops1('exit')

    # root# show run

    test1_result = ops1('show run')

    # test1_result = ops1('show run')

    # Test pass criteria
    # VM string test : access-list ip test1
    # Verify acl presents after created.
    assert search(
       r'(?!1\s+\S+)'.format(
                                         **locals()
                                       ), test1_result
    )

    # set_trace()
    step('################ T4a Apply ACL ###########')
    step('################ to interface ###############')
    step('################ ACL does not exist ###############')

    with pytest.raises(AclDoesNotExistException):
        with ops1.libs.vtysh.ConfigInterface('4') as ctx:
            ctx.apply_access_list_ip_in('test4')
    # The **acl** must be present in switch configuration.
    # Run commands
    # root(config-acl)# exit

    # ops1('exit')
    # ops1('exit')

    # root# show run
    # set_trace()
    step('################ T4b Apply ACL ###########')
    step('################ to interface ###############')
    step('################ Create ACL first ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.permit(
            '',
            '8', 'igmp', '1.2.3.4/255.0.0.0',
            '', '5.6.7.8/255.255.0.0', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'8\s+permit\s+igmp\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.0\.0\.0'
       '\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.255\.0\.0'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    # test1_result = ops1('show run')

    # Test pass criteria
    # VM string test : apply access-list ip test1 in
    # Verify acl presents after created.
    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    # set_trace()
    step('################ T5 Apply no ACL ###########')
    step('################ on interface ###############')

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.no_apply_access_list_ip_in('test4')
    # The **acl** must be present in switch configuration.
    # Run commands
    # root(config-acl)# exit

    # ops1('exit')
    # ops1('exit')

    # root# show run

    test1_result = ops1('show run')

    # test1_result = ops1('show run')

    # Test pass criteria
    # VM string test : apply access-list ip test1 in
    # Verify acl presents after created.
    assert search(
       r'(?!access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    # set_trace()
    step('################ T6 Replace an ACE ###########')
    step('################ in existing ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.permit('', '25', 'sctp', '1.2.3.4/8', '', '5.6.7.8/24', '')
    # The **acl** must be present in switch configuration.
    # Run commands
    # root(config-acl)# exit

    # ops1('exit')
    # ops1('exit')

    # root# show run

    test1_result = ops1('show run')

    # test1_result = ops1('show run')

    # Test pass criteria
    # VM string test : apply access-list ip test1 in
    # Verify acl presents after created.
    assert search(
       ''
       r'(25\s+permit\s+sctp\s+1\.2\.3\.4/8'
       '\s+5\.6\.7\.8/24)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.permit('', '25', 'sctp', '172.21.30.4/24', 'eq 10', 'any', 'eq 20')
    # The **acl** must be present in switch configuration.
    # Run commands
    # root(config-acl)# exit

    # ops1('exit')
    # ops1('exit')

    # root# show run

    test1_result = ops1('show run')

    # test1_result = ops1('show run')

    # Test pass criteria
    # VM string test : apply access-list ip test1 in
    # Verify acl presents after created.
    assert search(
       ''
       r'(25\s+permit\s+sctp\s+172\.21\.30\.4/24'
       '\s+eq\s+10\s+any\s+eq\s+20)'.format(
                                         **locals()
                                       ), test1_result
    )

    # set_trace()
    step('################ T7 Remove ACE from ACL ###########')
    step('################ Remove ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.no('25')
    # The **acl** must be present in switch configuration.
    # Run commands
    # root(config-acl)# exit

    # ops1('exit')
    # ops1('exit')

    # root# show run

    test1_result = ops1('show run')

    # test1_result = ops1('show run')

    # Test pass criteria
    # VM string test : apply access-list ip test1 in
    # Verify acl presents after created.
    assert search(
       r'(?!25\s+\S+)'.format(
                                         **locals()
                                       ), test1_result
    )

    step('################ Remove ACL ###############')
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test1')

    # root# show run

    test1_result = ops1('show run')

    # test2_result = ops1('show run')

    # Test pass criteria
    # Verify acl not presents.

    assert search(
         r'(?!access-list\s+ip\s+test1\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    # set_trace()
    step('################ T8 Add ACE sctp ###########')
    step('################ invalid L4 src port ###############')

    with pytest.raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
            ctx.permit(
                '',
                '30', 'sctp', '1.2.3.4/8', 'eq 66000',
                '5.6.7.8/24', 'eq 40')

    # set_trace()
    step('################ T9 Add ACE sctp ###########')
    step('################ valid L4 src, destn port ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.deny(
                '',
                '30', 'sctp', '1.2.3.4/8', 'eq 65000',
                '5.6.7.8/24', 'eq 40')

    test1_result = ops1('show run')

    assert search(
       ''
       r'(30\s+deny\s+sctp\s+1\.2\.3\.4/8'
       '\s+eq\s+65000\s+5\.6\.7\.8/24\s+eq\s+40)'.format(
                                         **locals()
                                       ), test1_result
    )

    # set_trace()
    step('################ T10 Add ACE sctp ###########')
    step('################ invalid L4 destination port ###############')

    with pytest.raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
            ctx.permit(
                '',
                '30', 'sctp', '1.2.3.4/8', 'eq 4',
                '5.6.7.8/24', 'eq 66000')

    # set_trace()
    step('################ T11 Add ACE sctp ###########')
    step('################ range min,max port ###############')
    step('################ ECHO WORKAROUND ###############')

    with pytest.raises(EchoCommandException):
        with ops1.libs.vtysh.ConfigAccessListIpTestname('test11') as ctx:
            ctx.permit(
                '',
                '40', 'sctp', '1.2.3.4/1', 'range 100 500',
                '5.6.7.8/32', 'range 40 50')

    test1_result = ops1('show run')

    assert search(
       ''
       r'(40\s+permit\s+sctp\s+1\.2\.3\.4/1'
       '\s+range\s+100\s+500\s+5\.6\.7\.8/32\s+range\s+40\s+50)'.format(
                                         **locals()
                                       ), test1_result
    )

    # set_trace()
    # step('################ T12 Add ACE sctp ###########')
    # step('################ range min,max port ###############')
    # step('################ NEGATIVE TEST PASSES ###############')
    # with pytest.raises(EchoCommandException):
    #     with ops1.libs.vtysh.ConfigAccessListIpTestname('test12') as ctx:
    #         ctx.permit(
    #             '',
    #             '12', 'sctp', '1.2.3.4/1', 'range 100 5',
    #             '5.6.7.8/32', 'range 400 50')

    # test1_result = ops1('show run')

    # assert search(
    #    ''
    #    r'(12\s+permit\s+sctp\s+1\.2\.3\.4/1'
    #    '\s+range\s+100\s+100\s+5\.6\.7\.8/32\s+range\s+400\s+50)'.format(
    #                                      **locals()
    #                                    ), test1_result
    # )

    set_trace()
    step('################ T12 Add ACE sctp ###########')
    step('################ range min,max port ###############')

    with pytest.raises(InvalidL4SourcePortRangeException):
        with ops1.libs.vtysh.ConfigAccessListIpTestname('test12') as ctx:
            ctx.permit(
                '',
                '12', 'sctp', 'any', 'range 100 5',
                'any', 'range 400 50')

    # set_trace()
    step('################ T13 Add ACE sctp ###########')
    step('################ invalid prefix ###############')

    with pytest.raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIpTestname('test13') as ctx:
            ctx.permit(
                '',
                '13', 'sctp', '1.2.3.4/40', 'eq 100 ',
                '5.6.7.8/60', 'eq 40')

    # test1_result = ops1('show run')

    # assert search(
    #   ''
    #  r'(?!13\s+permit\s+sctp\s+1\.2\.3\.4/40'
    #   '\s+eq\s+100\s+5\.6\.7\.8/60\s+eq\s+40)'.format(
    #                                     **locals()
    #                                   ), test1_result
    # )

    # set_trace()
    step('################ T14 Add ACE sctp ###########')
    step('################ invalid subnet mask ###############')

    with pytest.raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIpTestname('test14') as ctx:
            ctx.permit(
                '',
                '14', 'sctp', '1.2.3.4/259.1.1.1', 'eq 100 ',
                '5.6.7.8/271.0.0.0', 'eq 40')

    # set_trace()
    step('################ T15 Add ACE ###########')
    step('################ invalid numeric proto ###############')

    with pytest.raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIpTestname('test15') as ctx:
            ctx.permit(
                '',
                '15', '290', '1.2.3.4/259.1.1.1', '',
                '5.6.7.8/271.0.0.0', '')

    step('################ T16 Add ACE ###########')
    step('################ unsupported proto ###############')
    step('################ NEGATIVE TEST PASSES ###############')

    # set_trace()
    # with pytest.raises(UnknownCommandException):
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test16') as ctx:
        ctx.permit(
                '',
                '16', '0', '1.2.3.4', '',
                '5.6.7.8', '')

    step('################ T17 Add ACE ###########')
    step('################ L4 parameter ###############')
    step('################ FAILURE TCAM RESOURCES ###############')
    step('################  Command failed. ###############')

    i = 0
    with pytest.raises(TcamResourcesException):
        with ops1.libs.vtysh.ConfigAccessListIpTestname('test17') as ctx:
            for i in range(1, 4294967295):
                ctx.deny(
                    '',
                    i, 'udp', '1.2.3.4/8', 'eq 4',
                    '5.6.7.8/24', 'eq 40')

    test1_result = ops1('show run')

    # with pytest.raises(UnknownCommandException):
    # with ops1.libs.vtysh.ConfigAccessListIpTestname('test16') as ctx:
    #     ctx.permit(
    #             '',
    #             '16', 'tcp', '1.2.3.4', 'eq 21',
    #             '5.6.7.8', 'eq 80')

    # set_trace()
    step('################ T18 Add ACE ###########')
    step('################ Resequence ACEs###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip_resequence('test17', '1', '10')

    test1_result = ops1('show run')

    assert search(
        r'(5001\s+deny\s+udp\s+1\.2\.3\.4/8'
        '\s+eq\s+4\s+5\.6\.7\.8/24\s+eq\s+40)'.format(
                                   **locals()
                                   ), test1_result
                               )

    # set_trace()
    step('################ T19 Add ACE ###########')
    step('################ Resequence ACEs###############')
    step('################ Negative Test###############')

    # with ops1.libs.vtysh.Configure() as ctx:
    #     ctx.access_list_ip('test17')

    with pytest.raises(ResequenceNumberException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip_resequence('test17', '1', '1000000000')

    test1_result = ops1('show run')

    step('################ T20 Replace deny ACE ###########')
    step('################ with Permit ACE ###############')

    set_trace()

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test17') as ctx:
        ctx.permit('',
                   '4101', 'udp', '1.2.3.4/8', 'eq 4',
                   '5.6.7.8/24', 'eq 40')

    test1_result = ops1('show run')

    assert search(
       ''
       r'(4101\s+permit\s+udp\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/8'
       '\s+eq\s+4\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/24\s+eq\s+40)'.format(
                                         **locals()
                                       ), test1_result
    )

    step('################ T21 Remove ACE ###########')
    step('################ Negative Test ###############')
    step('################ POSITIVE TEST FAILS ###############')

    set_trace()

    # with pytest.raises(AceDoesNotExistException):
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test17') as ctx:
        ctx.permit('no',
                   '41010', 'udp', '1.2.3.4/8', 'eq 4',
                   '5.6.7.8/24', 'eq 40')

    step('################ T22 Remove ACE ###########')
    step('################ Positive Test ###############')

    set_trace()

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test17') as ctx:
        ctx.permit('no',
                   '4101', 'udp', '1.2.3.4/8', 'eq 4',
                   '5.6.7.8/24', 'eq 40')

    test1_result = ops1('show run')

    assert search(
       ''
       r'(?!4101\s+permit\s+udp\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/8'
       '\s+eq\s+4\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/24\s+eq\s+40)'.format(
                                         **locals()
                                       ), test1_result
    )
