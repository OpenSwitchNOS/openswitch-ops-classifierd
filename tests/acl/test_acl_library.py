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

from pytest import mark
from re import search
# from ipdb import set_trace
import pytest
import topology_lib_vtysh.exceptions

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

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

    # set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('viVtEST')

    test1_result = ops1('show run')

    assert search(
        r'access-list\s+ip\s+viVtEST'.format(
                                     **locals()
                                  ), test1_result
    )

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
    """
    # set_trace()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('test1')

    # The **acl** must be present in switch configuration.
    # Run commands

    # root# show run

    test1_result = ops1('show run')

    assert search(
         r'access-list\s+ip\s+test1'.format(
                                         **locals()
                                     ), test1_result
    )

    step('#################### access-list create ACL ####################')
    step('################ with name contains invalid char ###############')

    with pytest.raises(topology_lib_vtysh.exceptions.UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip('te st!$')

    test1_result = ops1('show run')
    assert search(
         r'(?!access-list\s+ip\s+.*\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ access-list create ACL ###############')
    step('with valid name  and non-alphanumeric')
    step(' characters  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('goodtest$!')

    test1_result = ops1('show run')
    assert search(
         r'(?!access-list\s+ip\s+.*\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ access-list create ACL ###############')
    step('################ with no name ###############')

    with pytest.raises(
            topology_lib_vtysh.exceptions.IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip(' ')

    test1_result = ops1('show run')
    assert search(
         r'(?!access-list\s+ip$)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ access-list create ACL ###############')
    step('################ with name > 64 chars ###############')
    longstr = (
                'creationofaccesscontrollisttestwith'
                'namegreaterthanmaximumallowedlengthshallberejected'
              )

    # set_trace()
    with pytest.raises(topology_lib_vtysh.exceptions.UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip('%s' % longstr)

    test1_result = ops1('show run')

    # no acl with name >64 chars

    assert search(
         r'(?!creationofaccesscontrollisttestwith)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('################ access-list delete ACL ###############')

    # set_trace()

    # Delete ACL

    # Configure create an **acl** on switch.
    # Run commands
    # root# config terminal
    # set_trace()

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

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test2')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test2\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    # Test fail criteria
    # set_trace()

    step('################ modify ACL ###############')
    step('################# with valid resequence number ##################')
    # Create ACL with valid name
    # Configure create an acl on switch with valid name.

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_ip('test1')

    test1_result = ops1('show run')

    assert search(
         r'(access-list\s+ip\s+test1\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    with pytest.raises(topology_lib_vtysh.exceptions.AclEmptyException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip_resequence('test1', 1, 10)

    test1_result = ops1('show run')

    assert search(
         r'(access-list\s+ip\s+test1\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    step('##################### Modify empty ACL ####################')
    step('############# with invalid resequence number ##############')

    # test1_result = ops1('access-list ip resequence test1 0 10')

    with pytest.raises(topology_lib_vtysh.exceptions.UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_ip_resequence('test1', 0, 10)
