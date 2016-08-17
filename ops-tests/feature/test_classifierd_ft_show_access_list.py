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
OpenSwitch Test for showing ACLs
"""

import time
from topology_lib_vtysh import exceptions
from topo_funcs import config_switch_l2
from pytest import fixture
from topo_defs import topology_1switch_def
import re

TOPOLOGY = topology_1switch_def


@fixture(scope='module')
def configure_acl_test(topology):
    ops1 = topology.get('ops1')
    assert ops1 is not None

    config_switch_l2(ops=ops1, vlan_id='2')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()


def test_show_access_list_with_no_acls(
        configure_acl_test, topology, step
        ):
    test = "Testing show access-list with no acls"
    step('##### {test} #####'.format(**locals()))
    ops1 = topology.get('ops1')
    assert ops1 is not None
    assert_no_core_dump(sw=ops1)

    all_show_access_list_cmds(
            sw=ops1, acl_name='test1', port_num='1', vlan_num='2', msg=test
            )

    assert_no_core_dump(sw=ops1)


def test_show_access_list_with_one_acl(
        configure_acl_test, topology, step
        ):
    test = "Testing show access-list with one acl applied to nothing"
    step('##### {test} #####'.format(**locals()))
    ops1 = topology.get('ops1')
    assert ops1 is not None
    assert_no_core_dump(sw=ops1)

    acl_name = 'test2'
    acl_addr_type = 'ip'
    port_num = '1'

    process_ctrl(sw=ops1, kill_opt='-stop', process='ops-switchd')

    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name,
            seq_num='1', action='permit', proto='any', src_ip='any',
            src_port='', dst_ip='any', dst_port='', count='', log=''
            )
    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name,
            seq_num='2', action='deny', proto='any', src_ip='any',
            src_port='', dst_ip='any', dst_port='', count='', log=''
            )

    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + " with ops-switchd SUSPENDED"
            )

    process_ctrl(sw=ops1, kill_opt='-cont', process='ops-switchd')
    # Sleep to let ops-switchd catch up
    time.sleep(6)
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + " with ops-switchd RUNNING")

    unconfigure_acl_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name
            )
    assert_no_core_dump(sw=ops1)


def test_show_access_list_with_one_acl_applied_to_one_port_ingress(
        configure_acl_test, topology, step
        ):

    test = "Testing show access-list with one acl applied to one port " \
           "ingress"
    step('##### {test} #####'.format(**locals()))
    ops1 = topology.get('ops1')
    assert ops1 is not None
    assert_no_core_dump(sw=ops1)

    acl_name = 'test3'
    acl_addr_type = 'ip'
    app_type = 'port'
    port_num = '1'
    direction = 'in'

    process_ctrl(sw=ops1, kill_opt='-stop', process='ops-switchd')

    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name,
            seq_num='1', action='permit', proto='udp', src_ip='any',
            src_port='', dst_ip='any', dst_port='', count='count', log=''
            )
    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name,
            seq_num='2', action='deny', proto='tcp', src_ip='any',
            src_port='', dst_ip='any', dst_port='', count='', log='log'
            )
    apply_acl_no_verify(
            sw=ops1, app_type=app_type, interface_num=port_num,
            acl_addr_type=acl_addr_type, acl_name=acl_name,
            direction=direction
            )

    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + " with ops-switchd SUSPENDED"
            )

    process_ctrl(sw=ops1, kill_opt='-cont', process='ops-switchd')
    # Sleep to let ops-switchd catch up
    time.sleep(6)
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + "with ops-switchd RUNNING"
            )

    process_ctrl(sw=ops1, kill_opt='-stop', process='ops-switchd')
    no_apply_interface_no_verify(
        sw=ops1, app_type=app_type, interface_num=port_num,
        acl_addr_type=acl_addr_type, acl_name=acl_name,
        direction=direction
        )
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + "after unapplying the acl and with ops-switchd "
            "SUSPENDED"
            )

    process_ctrl(sw=ops1, kill_opt='-cont', process='ops-switchd')
    # Sleep to let ops-switchd catch up
    time.sleep(6)
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + "after unapplying the acl and with ops-switchd "
            "RUNNING"
            )

    unconfigure_acl_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name
            )
    assert_no_core_dump(sw=ops1)


def test_show_access_list_with_one_acl_applied_to_one_port_egress(
        configure_acl_test, topology, step
        ):

    test = "Testing show access-list with one acl applied to one port " \
           "egress"
    step('##### {test} #####'.format(**locals()))
    ops1 = topology.get('ops1')
    assert ops1 is not None
    assert_no_core_dump(sw=ops1)

    acl_name = 'test4'
    acl_addr_type = 'ip'
    app_type = 'port'
    port_num = '1'
    direction = 'out'

    process_ctrl(sw=ops1, kill_opt='-stop', process='ops-switchd')

    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name,
            seq_num='1', action='permit', proto='udp', src_ip='1.1.1.1',
            src_port='', dst_ip='1.1.1.2', dst_port='', count='count',
            log='log'
            )
    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name,
            seq_num='2', action='deny', proto='icmp', src_ip='any',
            src_port='', dst_ip='any', dst_port='', count='', log=''
            )
    apply_acl_no_verify(
            sw=ops1, app_type=app_type, interface_num=port_num,
            acl_addr_type=acl_addr_type, acl_name=acl_name,
            direction=direction
            )

    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + " with ops-switchd SUSPENDED"
            )

    process_ctrl(sw=ops1, kill_opt='-cont', process='ops-switchd')
    # Sleep to let ops-switchd catch up
    time.sleep(6)
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + " with ops-switchd RUNNING"
            )

    process_ctrl(sw=ops1, kill_opt='-stop', process='ops-switchd')
    no_apply_interface_no_verify(
        sw=ops1, app_type=app_type, interface_num=port_num,
        acl_addr_type=acl_addr_type, acl_name=acl_name,
        direction=direction
        )
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + "after unapplying the acl and with ops-switchd "
            "SUSPENDED"
            )

    process_ctrl(sw=ops1, kill_opt='-cont', process='ops-switchd')
    # Sleep to let ops-switchd catch up
    time.sleep(6)
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + "after unapplying the acl and with ops-switchd "
            "RUNNING"
            )

    unconfigure_acl_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name
            )
    assert_no_core_dump(sw=ops1)


def test_show_access_list_with_one_acl_applied_to_one_port_both_directions(
        configure_acl_test, topology, step
        ):

    test = "Testing show access-list with one acl applied to one port " \
           "in both directions"
    step('##### {test} #####'.format(**locals()))
    ops1 = topology.get('ops1')
    assert ops1 is not None
    assert_no_core_dump(sw=ops1)

    acl_name = 'test5'
    acl_addr_type = 'ip'
    app_type = 'port'
    port_num = '1'
    dir_list = ['in', 'out']

    process_ctrl(sw=ops1, kill_opt='-stop', process='ops-switchd')

    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name,
            seq_num='1', action='permit', proto='udp', src_ip='1.1.1.1',
            src_port='', dst_ip='1.1.1.2', dst_port='', count='', log='log'
            )
    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name,
            seq_num='2', action='deny', proto='icmp', src_ip='any',
            src_port='', dst_ip='any', dst_port='', count='count', log=''
            )
    for dir_ in dir_list:
        apply_acl_no_verify(
                sw=ops1, app_type=app_type, interface_num=port_num,
                acl_addr_type=acl_addr_type, acl_name=acl_name, direction=dir_
                )

    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + " with ops-switchd SUSPENDED")

    process_ctrl(sw=ops1, kill_opt='-cont', process='ops-switchd')
    # Sleep to let ops-switchd catch up
    time.sleep(6)
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + " with ops-switchd RUNNING")

    process_ctrl(sw=ops1, kill_opt='-stop', process='ops-switchd')
    for dir_ in dir_list:
        no_apply_interface_no_verify(
            sw=ops1, app_type=app_type, interface_num=port_num,
            acl_addr_type=acl_addr_type, acl_name=acl_name, direction=dir_
            )
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + " after unapplying the acl and with ops-switchd "
            "SUSPENDED"
            )

    process_ctrl(sw=ops1, kill_opt='-cont', process='ops-switchd')
    # Sleep to let ops-switchd catch up
    time.sleep(6)
    all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name, port_num=port_num, vlan_num='2',
            msg=test + " after unapplying the acl and with ops-switchd "
            "RUNNING"
            )

    unconfigure_acl_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name
            )
    assert_no_core_dump(sw=ops1)


def test_show_access_list_with_two_acls_applied_to_one_port_both_directions(
        configure_acl_test, topology, step
        ):

    test = "Testing show access-list with two acl applied to one port " \
           "in two different directions"
    step('##### {test} #####'.format(**locals()))
    ops1 = topology.get('ops1')
    assert ops1 is not None
    assert_no_core_dump(sw=ops1)

    acl_name_list = ['test5_ingress', 'test5_egress']
    acl_addr_type = 'ip'
    app_type = 'port'
    port_num = '1'
    dir_list = ['in', 'out']

    process_ctrl(sw=ops1, kill_opt='-stop', process='ops-switchd')

    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name_list[0],
            seq_num='1', action='permit', proto='udp', src_ip='1.1.1.1',
            src_port='range 1 3', dst_ip='1.1.1.2', dst_port='', count='count',
            log='log'
            )
    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name_list[0],
            seq_num='2', action='deny', proto='255', src_ip='any',
            src_port='', dst_ip='any', dst_port='', count='',
            log=''
            )
    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name_list[1],
            seq_num='1', action='permit', proto='1', src_ip='any',
            src_port='', dst_ip='1.1.1.1', dst_port='', count='count',
            log=''
            )
    configure_acl_l3_no_verify(
            sw=ops1, acl_addr_type=acl_addr_type, acl_name=acl_name_list[1],
            seq_num='2', action='permit', proto='icmp', src_ip='any',
            src_port='', dst_ip='1.1.1.2', dst_port='', count='',
            log='log'
            )

    for i in list(range(2)):
        apply_acl_no_verify(
                sw=ops1, app_type=app_type, interface_num=port_num,
                acl_addr_type=acl_addr_type, acl_name=acl_name_list[i],
                direction=dir_list[i]
                )

    for i in list(range(2)):
        all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name_list[i], port_num=port_num,
            vlan_num='2', msg=test + " with ops-switchd SUSPENDED"
            )

    process_ctrl(sw=ops1, kill_opt='-cont', process='ops-switchd')
    # Sleep to let ops-switchd catch up
    time.sleep(6)
    for i in list(range(2)):
        all_show_access_list_cmds(
            sw=ops1, acl_name=acl_name_list[i], port_num=port_num,
            vlan_num='2', msg=test + " with ops-switchd RUNNING")

    process_ctrl(sw=ops1, kill_opt='-stop', process='ops-switchd')

    for i in list(range(2)):
        no_apply_interface_no_verify(
            sw=ops1, app_type=app_type, interface_num=port_num,
            acl_addr_type=acl_addr_type, acl_name=acl_name_list[i],
            direction=dir_list[i]
            )

    for i in list(range(2)):
        all_show_access_list_cmds(
                sw=ops1, acl_name=acl_name_list[i], port_num=port_num,
                vlan_num='2', msg=test + " after unapplying the acl and with"
                " ops-switchd SUSPENDED"
        )

    process_ctrl(sw=ops1, kill_opt='-cont', process='ops-switchd')
    # Sleep to let ops-switchd catch up
    time.sleep(6)
    for i in list(range(2)):
        all_show_access_list_cmds(
                sw=ops1, acl_name=acl_name_list[i], port_num=port_num,
                vlan_num='2', msg=test + " after unapplying the acl and with"
                " ops-switchd RUNNING"
        )

    for i in list(range(2)):
        unconfigure_acl_no_verify(
                sw=ops1, acl_addr_type='ip', acl_name=acl_name_list[i]
                )
    assert_no_core_dump(sw=ops1)


def process_ctrl(sw, kill_opt, process):
    assert kill_opt in ('-stop', '-cont')
    assert process in ('ops-switchd')

    _shell = sw.get_shell('bash')
    _shell.send_command(
            r'kill {kill_opt} $(pidof {process})'.format(**locals())
            )

    retval = _shell.get_response(connection=None)
    print(">>>>>> The shell response was <{retval}>"
          .format(**locals()))
    assert retval == ''

    _shell.send_command(
            r'ps aux | grep "{process}"'.format(**locals())
            )
    result = _shell.get_response()
    assert result != ''
    result_list = result.split('\n')
    for result_line in result_list:
        print("Result line is <{result_line}>".format(**locals()))
        ps_dict = re.search(
                r'^(?P<user>\S+)\s+(?P<pid>\S+)\s+(?P<cpu>\S+)\s+(?P<mem>\S+)'
                '\s+(?P<VSZ>\S+)\s+(?P<RSS>\S+)\s+(?P<TTY>\S+)\s+(?P<stat>\S+)'
                '\s+(?P<start>\S+)\s+(?P<time>\S+)\s+(?P<process>.+)',
                result_line).groupdict()
        print("ps_dict is <{ps_dict}>".format(**locals()))
        if 'grep' not in ps_dict['process']:
            if process in ps_dict['process']:
                # The process states from "man ps" are descriped below:
                #     D    uninterruptible sleep (usually IO)
                #     R    running or runnable (on run queue)
                #     S    interruptible sleep (waiting for an event to
                #              complete)
                #     T    stopped, either by a job control signal or because
                #              it is being traced
                #     W    paging (not valid since the 2.6.xx kernel)
                #     X    dead (should never be seen)
                #     Z    defunct ("zombie") process, terminated but not
                #              reaped by its parent
                if kill_opt == '-stop':
                    assert 'T' in ps_dict['stat']
                elif kill_opt == '-cont':
                    assert re.search(r'(R|S)', ps_dict['stat'])
                else:
                    print(
                            ">>>>> kill_op {kill_op} not supported <<<<<"
                            .format(**locals())
                        )
                break


def all_show_access_list_cmds(sw, acl_name, port_num, vlan_num, msg):
    """
    executes all varitions of show access-list

    show access-list [{'{'}interface|vlan} <id> [in|out]] [ip] [<acl-name>]
    [commands] [configuration]
    """
    assert sw is not None
    assert isinstance(acl_name, str)
    assert isinstance(port_num, str)
    assert isinstance(vlan_num, str)
    assert isinstance(msg, str)

    print("~~~~~ {msg} ~~~~~".format(**locals()))
    cmd = 'show run'
    print(
        ">>>>> Below is the result for the command '{cmd}' <<<<<"
        .format(**locals())
        )
    result = sw(cmd)
    print(">>>>> END <<<<<")

    cmd_config = [
            '',
            'commands',
            'configuration',
            'commands configuration'
            ]
    acl_app_types = [
            '',
            'interface {port_num}'.format(**locals()),
            'interface {port_num} in'.format(**locals()),
            'interface {port_num} out'.format(**locals()),
            'vlan {vlan_num}'.format(**locals()),
            'vlan {vlan_num} in'.format(**locals()),
            'vlan {vlan_num} out'.format(**locals())
            ]
    acl_addr_types = [
            '',
            'ip',
            'ip {acl_name}'.format(**locals())
            ]
    for app_type in acl_app_types:
        for addr_type in acl_addr_types:
            for suffix in cmd_config:
                print("~~~~~ {msg} ~~~~~".format(**locals()))
                cmd = 'show access-list {app_type} {addr_type} {suffix}' \
                      .format(**locals())
                cmd = re.sub('\s+', ' ', cmd.strip())
                print(
                    ">>>>> Below is the result for the command '{cmd}' <<<<<"
                    .format(**locals())
                    )
                result = sw(cmd)
                print(">>>>> END <<<<<")

    acl_app_types = [
            '',
            'interface {port_num}'.format(**locals()),
            'interface {port_num} in'.format(**locals()),
            'interface {port_num} out'.format(**locals()),
            'vlan {vlan_num}'.format(**locals()),
            'vlan {vlan_num} in'.format(**locals()),
            'vlan {vlan_num} out'.format(**locals())
            ]
    acl_addr_types = [
            'ip {acl_name}'.format(**locals())
            ]
    for app_type in acl_app_types:
        for addr_type in acl_addr_types:
            print("~~~~~ {msg} ~~~~~".format(**locals()))
            cmd = 'show access-list hitcounts {addr_type} {app_type}' \
                  .format(**locals())
            cmd = re.sub('\s+', ' ', cmd.strip())
            print(
                ">>>>> Below is the result for the command '{cmd}' <<<<<"
                .format(**locals())
                )
            result = sw(cmd)
            print(">>>>> END <<<<<")


def configure_acl_l3_no_verify(
            sw, acl_addr_type, acl_name, seq_num, action, proto, src_ip,
            src_port, dst_ip, dst_port, count, log=''
        ):
    """
    Configure an ACL with one permit or one deny rule
    """

    assert sw is not None
    assert acl_addr_type in ('ip')  # Will add ipv6 in future, but not mac
    assert isinstance(acl_name, str)
    assert isinstance(seq_num, str)
    assert action in ('permit', 'deny')
    assert isinstance(proto, str)
    assert isinstance(src_ip, str)
    assert isinstance(src_port, str)
    assert isinstance(dst_ip, str)
    assert isinstance(dst_port, str)
    assert count in ('count', '')
    assert log in ('log', '')

    if acl_addr_type == 'ip':
        with sw.libs.vtysh.ConfigAccessListIpTestname(acl_name) as ctx:
            try:
                getattr(ctx, action)(
                          '',
                          seq_num, proto, src_ip, src_port,
                          dst_ip, dst_port, count, log
                          )
            except exceptions.EchoCommandException:
                # If the command plus the command prompt is exactly
                # 80 characters then vtysh will echo the command back
                # in a telnet session and confuse the vtysh library.
                # This is a known bug.
                print("<<<<< EchoCommandException >>>>>")
            except exceptions.UnknownVtyshException:
                # When the command plus the command promt is longer
                # then 80 characters then the telnet response confuses
                # the vtysh library. This is a known bug.
                print("<<<<< UnknownVtyshException >>>>>")
    else:
        # TODO: add ipv6 here
        assert False


def apply_acl_no_verify(
            sw, app_type, interface_num, acl_addr_type, acl_name, direction
        ):
    """
    Apply ACL on interface in ingress or egress direction
    """
    assert sw is not None
    assert app_type in ('port')
    assert acl_addr_type in ('ip')

    # If the app_type is port, then interface_num is the port number the acl
    # should be applied to.  If vlan, then the VLAN number.  If tunnel, then
    # tunnel number.
    assert isinstance(interface_num, str)
    assert isinstance(acl_name, str)
    assert direction in ('in', 'out')

    if app_type == 'port':
        if direction == 'in':
            with sw.libs.vtysh.ConfigInterface(interface_num) as ctx:
                ctx.apply_access_list_ip_in(acl_name)
        elif direction == 'out':
            with sw.libs.vtysh.ConfigInterface(interface_num) as ctx:
                ctx.apply_access_list_ip_out(acl_name)
        else:
            # Undefined direction
            assert(False)
    else:
        # Undefined ACL application type
        assert(False)


def no_apply_interface_no_verify(
        sw, app_type, interface_num, acl_addr_type, acl_name, direction
        ):

    assert sw is not None
    assert app_type in ('port', 'vlan')
    assert isinstance(interface_num, str)
    assert acl_addr_type in ('ip', 'ipv6', 'mac')
    assert isinstance(acl_name, str)
    assert direction in ('in', 'out')

    if app_type == 'port':
        if acl_addr_type == 'ip':
            with sw.libs.vtysh.ConfigInterface(interface_num) as ctx:
                if direction == 'in':
                    ctx.no_apply_access_list_ip_in(acl_name)
                    pass
                else:
                    ctx.no_apply_access_list_ip_out(acl_name)
                    pass
        else:
            print(
                "<%s> address type is not supported in no_apply_interface()"
                % (acl_addr_type)
                )
            assert False
    else:
        print(
            "<%s> ACL application type is not supported in"
            " no_apply_interface()" % (app_type)
            )
        assert False


def unconfigure_acl_no_verify(sw, acl_addr_type, acl_name):
    """
    Remove an ACL
    """
    assert sw is not None
    assert acl_addr_type in ('ip', 'ipv6', 'mac')
    assert isinstance(acl_name, str)

    if acl_addr_type == 'ip':
        with sw.libs.vtysh.Configure() as ctx:
            ctx.no_access_list_ip(acl_name)
    else:
        # ipv6 and mac not implemented yet
        assert False


def assert_no_core_dump(sw):
    assert 'No core dumps are present' in sw('show core-dump')
