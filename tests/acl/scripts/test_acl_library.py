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
from topology_lib_vtysh.exceptions import IncompleteCommandException
# from topology_lib_vtysh.exceptions import PermittedException
from topology_lib_vtysh.exceptions import AclEmptyException
# from topology_lib_vtysh.exceptions import InvalidQnCommandException

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


@mark.test_id(10401)
def test_acl_create_delete(topology, step):
    """
    Test the creation and deletion of access control list.

    Build a topology of one switch. Tested the ability to properly add ACL,
    delete ACL.
    """
    ops1 = topology.get('ops1')

    assert ops1 is not None

    step('################ T1 access-list create ACL ###########')
    step('################ with one number ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('1')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+1'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T2 access-list create ACL ###########')
    step('################ with apostrophe ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('1\'s')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+1\'s'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T3 access-list create ACL ###########')
    step('################ with quotation ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('1\"s')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+1\"s'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T4 access-list create ACL ###########')
    step('################ with @ sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('1@s')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+1@s'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T5 access-list create ACL ###########')
    step('################ with 1 char ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('z')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+z'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T6 access-list create ACL ###########')
    step('################ with grave accent ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v`v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v`v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T7 access-list create ACL ###########')
    step('################ with number sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v+v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v\+v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T8 access-list create ACL ###########')
    step('################ with percent sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v%v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v%v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T9 access-list create ACL ###########')
    step('################ with greater sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v>v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v>v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T10 access-list create ACL ###########')
    step('################ with lesser sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v<v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v<v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T11 access-list create ACL ###########')
    step('################ with exclamation sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v!v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v!v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T12 access-list create ACL ###########')
    step('################ with period sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v.v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v\.v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T13 access-list create ACL ###########')
    step('################ with brackets ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v(v)')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v\(v\)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T14 access-list create ACL ###########')
    step('################ with asterisk sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v*v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v\*v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T15 access-list create ACL ###########')
    step('################ with dollar sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v$v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v\$v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T16 access-list create ACL ###########')
    step('################ with semicolon sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v;v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v;v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T17 access-list create ACL ###########')
    step('################ with colon sign ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v:v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v:v'.format(
                                         **locals()
                                     ), test1_result
    )

    # step('################ T17 access-list create ACL ###########')
    # step('################ with question mark ###############')

    set_trace()

    # with pytest.raises(InvalidQnCommandException):
    #     with ops1.libs.vtysh.Configure() as ctx:
    #         ctx.access_list_ip('v?v')

    # test1_result = ops1('show run')

    # assert search(
    #      r'(?!access-list\s+ip\s+v\?v'.format(
    #                                      **locals()
    #                                  ), test1_result
    # )

    # step('################ T18 access-list create ACL ###########')
    # step('################ with caret ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v^v')

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+v\^v'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ T19 access-list create ACL ###########')
    step('################ with braces ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v{v}')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v{{v}}'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T20 access-list create ACL ###########')
    step('################ with hyphen  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v-v')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v-v'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T21 access-list create ACL ###########')
    step('################ with equal  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v=v')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v=v'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T22 access-list create ACL ###########')
    step('################ with tilde  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v~v')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v~v'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T23 access-list create ACL ###########')
    step('################ with slash  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v/v')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v\/v'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T24 access-list create ACL ###########')
    step('################ with backslash  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v\\v')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v\\v'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T25 access-list create ACL ###########')
    step('################ with pipe  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v|v')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v|v'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T26 access-list create ACL ###########')
    step('################ with ampersand  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v&v')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v&v'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T26 access-list create ACL ###########')
    step('################ with dash  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v-v')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v-v'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T27 access-list create ACL ###########')
    step('################ with underscore  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('v_v')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+v_v'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T28 access-list create ACL ###########')
    step('################ with Capitalization 1  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('VIvTest')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+VIvTest'.format(
                                     **locals()
                                  ), test1_result
    )

    step('################ T29 access-list create ACL ###########')
    step('################ with Capitalization 2  ###############')

    set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('viVtEST')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+viVtEST'.format(
                                     **locals()
                                  ), test1_result
    )

    # VM integrate begin
    step('################ T30 access-list create ACL ###############')
    step('################ with valid name ###############')

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
    # set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('test1')

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
         r'access-list\s+ip\s+test1'.format(
                                         **locals()
                                     ), test1_result
    )
    # Test fail criteria

    step('#################### access-list create ACL ####################')
    step('################ with name contains invalid char ###############')

    # Create ACL with name contains invalid char

    # Configure create an **acl** on switch with valid name.
    # Run commands
    # root# config terminal

    # ops1('config terminal')

    # ERROR root(config)# access-list ip t&?e st!$

    # set_trace()
    # test1_result = ops1('access-list ip t&?e st!$')
    # test1_result = ops1('access-list ip te st!$')

    with pytest.raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip('te st!$')

    # Test pass criteria
    # Verify acl not presents.
    # The command outputs:
    # % Unknown command.
    # assert search(
    #     r'(Unknown command.|\s+NAME\s+ACL\s+name)'.format(
    #                                     **locals()
    #                                 ), test1_result
    # )

    # The **acl** must not be present in switch configuration.
    # Run commands
    # root(config-acl)# exit
    # VM Above line incorrect
    # root# show run

    # ops1('exit')

    # test1_result = ops1('show run')

    test1_result = ops1('show run')
    assert search(
         r'(?!access-list\s+ip\s+.*\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ access-list create ACL ###############')
    step('with valid name  and non-alphanumeric')
    step(' characters  ###############')

    # VM start case without space - normal
    # ops1('config terminal')

    # root(config)# access-list ip t st!$

    # set_trace()
    # test1_result = ops1('access-list ip goodtest$!')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('goodtest$!')

#    assert search(
#         r'(access-list\s+ip\s+\S)'.format(
#                                         **locals()
#                                     ), test1_result
#    )

    # ops1('exit')
    # ops1('exit')

    # test1_result = ops1('show run')

    test1_result = ops1('show run')
    assert search(
         r'(?!access-list\s+ip\s+.*\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    # VM integrate end

    step('################ access-list create ACL ###############')
    step('################ with no name ###############')
    # VM start case without space - normal
    # ops1('config terminal')

    # root(config)# access-list ip

    # set_trace()
    with pytest.raises(IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip(' ')

    # test1_result = ops1('access-list ip')

    # assert search(
    #      r'(Command incomplete.)'.format(
    #                                      **locals()
    #                                  ), test1_result
    # )

    # ops1('exit')

    # test1_result = ops1('show run')

    test1_result = ops1('show run')
    assert search(
         r'(?!access-list\s+ip$)'.format(
                                         **locals()
                                     ), test1_result
    )

    # Configure create an **acl** on switch with name greater than maximum \
    # allowed length.
    # Run commands
    # root# config terminal

    # ops1('config terminal')

    # root(config)# access-list ip "creationofaccesscontrollisttestwith \

    # namegreaterthanmaximumallowedlengthshallberejected"

    # longstr = """ creationofaccesscontrollisttestwith
    #              namegreaterthanmaximumallowedlengthshallberejected """

    step('################ access-list create ACL ###############')
    step('################ with name > 64 chars ###############')
    longstr = (
                'creationofaccesscontrollisttestwith'
                'namegreaterthanmaximumallowedlengthshallberejected'
              )

    # test1_result = ops1(
    #                'access-list ip creationofaccesscontrollisttestwith'
    #                'namegreaterthanmaximumallowedlengthshallberejected'
    #                   )

    # The **acl** must not be present in switch configuration.
    # Run commands

    # assert search(
    #     r'(Unknown command)'.format(
    #                                     **locals()
    #                                 ), test1_result
    # )

    # root(config)# exit

    # ops1('exit')

    set_trace()
    with pytest.raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip('%s' % longstr)

    # root# show run

    test1_result = ops1('show run')

    # no acl with name >64 chars

    assert search(
         r'(?!creationofaccesscontrollisttestwith)'.format(
                                         **locals()
                                     ), test1_result
    )

    # test1_result = ops1('show run')

    # Test pass criteria
    # Verify acl not presents.
    # The command outputs:
    # % Unknown command.
    # Test fail criteria

    step('################ access-list delete ACL ###############')

    set_trace()

    # Delete ACL

    # Configure create an **acl** on switch.
    # Run commands
    # root# config terminal
    set_trace()

    # ops1('config terminal')

    # root(config)# access-list ip test2

    # test1_result = ops1('access-list ip test2')

    # The **acl** must be present in switch configuration.

    # ops1('exit')
    # ops1('exit')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('test2')

    test1_result = ops1('show run')

    assert search(
         r'(access-list\s+ip\s+test2\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    # Configure delete the created **acl** on switch.
    # Run commands

    # ops1('config terminal')

    # root(config)# no access-list ip test2

    # test1_result = ops1('no access-list ip test2')

    # The **acl** must not be present in switch configuration.

    # Run commands
    # root(config-acl)# exit

    # ops1('exit')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test2')

    # root# show run

    test1_result = ops1('show run')

    # test2_result = ops1('show run')

    # Test pass criteria
    # Verify acl not presents.

    assert search(
         r'(?!access-list\s+ip\s+test2\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    # Test fail criteria
    set_trace()

    step('################ modify ACL ###############')
    step('################# with valid resequence number ##################')
    # Create ACL with valid name
    # Configure create an acl on switch with valid name.
    # Run following commands
    # root# config terminal

    # ops1('config terminal')
    # root(config)# access-list ip resequence test1 1 10
    # ops1('access-list ip test1')

    # ops1('exit')
    # ops1('exit')
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('test1')

    test1_result = ops1('show run')

    assert search(
         r'(access-list\s+ip\s+test1\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    set_trace()
    # ops1('config terminal')

    # test1_result = ops1('access-list ip resequence test1 1 10')

    # assert search(
    #     r'(ACL\s+is\s+empty)'.format(
    #                                     **locals()
    #                                 ), test1_result
    # )
    with pytest.raises(AclEmptyException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip_resequence('test1', 1, 10)

    # Run following commands
    # root(config-acl)# exit

    # ops1('exit')

    # VM redundant below?
    # root# show run
    # test1_result = ops1('show run')

    test1_result = ops1('show run')

    assert search(
         r'(access-list\s+ip\s+test1\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    # Test pass criteria
    # The command outputs:
    # % ACL is empty
    # Test fail criteria

    step('##################### Modify empty ACL ####################')
    step('############# with invalid resequence number ##############')
    # Create ACL with valid name
    # Configure create an acl on switch with valid name.
    # Run following commands
    # root# config terminal
    # root(config)# access-list ip resequence test1 0 10

    # ops1('config terminal')
    set_trace()

    # test1_result = ops1('access-list ip resequence test1 0 10')

    # assert search(
    #      r'(Unknown command)'.format(
    #                                      **locals()
    #                                  ), test1_result
    # )

    # ops1('exit')
    with pytest.raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip_resequence('test1', 0, 10)

    # Run following commands
    # root(config-acl)# exit
    # root# show run
    # test1_result = ops1('show run')
    # Test pass criteria
    # The command outputs:
    # % Unknown command.
    # Test fail criteria
