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

import re

import pytest
from copy import deepcopy
import sys
import time

from pytest import raises
from topology_lib_vtysh.exceptions import IncompleteCommandException
from topology_lib_vtysh.exceptions import TcamResourcesException
from topology_lib_vtysh.exceptions import UnknownCommandException

TOPOLOGY = """
# +-------+
# |  ops1 |
# +-------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1

# Ports
ops1:1
"""

ops1 = None
p1 = None
switch_ip = None

@pytest.fixture(scope="module")
def setup(topology):
    global ops1
    ops1 = topology.get("ops1")
    assert ops1 is not None

    global p1
    p1 = ops1.ports['1']
    assert p1 is not None

    global switch_ip
    switch_ip = get_switch_ip(ops1)
    assert switch_ip is not None

    with ops1.libs.vtysh.ConfigVlan('1') as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface(format('{p1}')) as ctx:
        ctx.no_routing()
        ctx.vlan_access(1)
        ctx.vlan_trunk_allowed(1)
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.no_shutdown()

    wait_for_queue_statistics(ops1)

def wait_for_queue_statistics(ops1):
    out = ops1(format('show interface {p1} queues'))
    i = 0
    while 'Q0' not in out:
        i = i + 1
        time.sleep(1)
        assert i < 90
        out = ops1(format('show interface {p1} queues'))

def get_switch_ip(switch):
    switch_ip = switch('python -c \"import socket; '
                       'print socket.gethostbyname(socket.gethostname())\"',
                       shell='bash')
    switch_ip = switch_ip.rstrip('\r\n')
    return switch_ip

def format(s):
    return s.format(**globals())

### Returns true if the given string contains a line that contains each
### string in the given list of strings.
def contains_line_with(string, strings):
    for line in string.splitlines():
        found_all_strings = True
        for s in strings:
            found_all_strings = found_all_strings and (s in line)

        if found_all_strings:
            return True

    return False

def setUp_qosApplyGlobal():
    with ops1.libs.vtysh.ConfigQueueProfile('profile1') as ctx:
        ctx.map_queue_local_priority('4', '3')
        ctx.map_queue_local_priority('5', '2')
        ctx.map_queue_local_priority('6', '1')
        ctx.map_queue_local_priority('7', '0')
        ctx.map_queue_local_priority('0', '7')
        ctx.map_queue_local_priority('1', '6')
        ctx.map_queue_local_priority('2', '5')
        ctx.map_queue_local_priority('3', '4')
    with ops1.libs.vtysh.ConfigScheduleProfile('profile1') as ctx:
        ctx.dwrr_queue_weight('4', '40')
        ctx.dwrr_queue_weight('5', '50')
        ctx.dwrr_queue_weight('6', '60')
        ctx.dwrr_queue_weight('7', '70')
        ctx.dwrr_queue_weight('0', '1')
        ctx.dwrr_queue_weight('1', '10')
        ctx.dwrr_queue_weight('2', '20')
        ctx.dwrr_queue_weight('3', '30')

    with ops1.libs.vtysh.ConfigQueueProfile('IncompleteProfile') as ctx:
        ctx.map_queue_local_priority('0', '0')
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_schedule_profile('IncompleteProfile')

def setUp_qosDscpPort():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_trust()
    with ops1.libs.vtysh.ConfigInterface(format('{p1}')) as ctx:
        ctx.no_qos_trust()
        ctx.no_qos_dscp()

def get_local_priority_range():
    out = ops1.libs.vtysh.show_qos_cos_map("default")

    min_local_priority = sys.maxsize
    max_local_priority = -1
    for key, value in out.items():
        local_priority = int(value['local_priority'])

        if local_priority > max_local_priority:
            max_local_priority = local_priority

        if local_priority < min_local_priority:
            min_local_priority = local_priority

    local_priority_range = [min_local_priority, max_local_priority]
    return local_priority_range

def case_qosCosMapShowRunningConfigWithDefault():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_cos_map_local_priority_color_name(
            '1', '0', 'green', 'Background')

    # TODO: Use vtysh communication library.
    out = ops1('show running-config')
    assert 'cos-map' not in out
    assert 'code_point' not in out
    assert 'local_priority' not in out
    assert 'color' not in out
    assert 'name' not in out

def case_qosCosMapShow():
    code_point = '7'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_cos_map_local_priority_color_name(
            code_point, '2', 'yellow', 'MyName2')

    out = ops1.libs.vtysh.show_qos_cos_map()
    assert out[code_point]['code_point'] == '7'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'yellow'
    assert out[code_point]['name'] == 'MyName2'

    out = ops1.libs.vtysh.show_qos_cos_map('default')
    assert out[code_point]['code_point'] == '7'
    assert out[code_point]['local_priority'] == '7'
    assert out[code_point]['color'] == 'green'
    assert out[code_point]['name'] == 'Network_Control'

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_cos_map(code_point)

def case_qosCosPortShowRunningConfig():
    # This command is not supported in dill.
    return
    setup_qosCosPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos cos 1'))
    out = ops1(format('do show running-config'))
    assert 'override' in out

def case_qosCosPortShowRunningConfigInterface():
    # This command is not supported in dill.
    return
    setup_qosCosPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos cos 1'))
    out = ops1(format('do show running-config interface {p1}'))
    assert 'override' in out

def case_qosCosPortShowInterface():
    # This command is not supported in dill.
    return
    setup_qosCosPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos cos 1'))
    out = ops1(format('do show interface {p1}'))
    assert 'override' in out
    setup_qosCosPort()

def case_qosDscpMapShowRunningConfigWithDefault():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_dscp_map_local_priority_color_name(
            '38', '4', 'red', 'AF43')

    # TODO: Use vtysh communication library.
    out = ops1('show running-config')
    assert 'dscp-map' not in out
    assert 'code_point' not in out
    assert 'local_priority' not in out
    assert 'color' not in out
    assert 'name' not in out

def case_qosDscpMapShow():
    code_point = '38'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_dscp_map_local_priority_color_name(
            code_point, '2', 'yellow', 'MyName2')

    out = ops1.libs.vtysh.show_qos_dscp_map()
    assert out[code_point]['code_point'] == '38'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'yellow'
    assert out[code_point]['name'] == 'MyName2'

    out = ops1.libs.vtysh.show_qos_dscp_map('default')
    assert out[code_point]['code_point'] == '38'
    assert out[code_point]['local_priority'] == '4'
    assert out[code_point]['color'] == 'red'
    assert out[code_point]['name'] == 'AF43'

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_dscp_map(code_point)

def case_qosDscpPortShow():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.ConfigInterface(format('{p1}')) as ctx:
        ctx.qos_trust('none')
        ctx.qos_dscp('1')

    # TODO: Use vtysh communication library.
    out = ops1('show running-config')
    assert 'qos dscp 1' in out
    out = ops1(format('show running-config interface {p1}'))
    assert 'qos dscp 1' in out
    out = ops1(format('show interface {p1}'))
    assert 'override' in out

def case_qosQueueProfileShowCommand():
    out = ops1.libs.vtysh.show_qos_queue_profile('profile1')
    assert out['1']['queue_num'] == '1'
    assert out['1']['local_priorities'] == '6'

def case_qosQueueProfileShowCommandWithIllegalName():
    # TODO: Use vtysh communication library.
    out = ops1(format('show qos queue-profile '
                         'NameThatIsLongerThan64Characterssssssssssssssss'
                         'ssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('show qos queue-profile '
                         'NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosQueueProfileShowCommandShowsAllProfiles():
    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['IncompleteProfile']['profile_status'] == 'incomplete'
    assert out['profile1']['profile_status'] == 'complete'
    assert out['default']['profile_status'] == 'applied'

def case_qosQueueProfileShowCommandFactoryDefault():
    out = ops1.libs.vtysh.show_qos_queue_profile('factory-default')
    assert out['0']['queue_num'] == '0'

def case_qosQueueProfileShowCommandWithNonExistentProfile():
    # TODO: Use vtysh communication library.
    out = ops1(format('show qos queue-profile NonExistent'))
    assert 'does not exist' in out

def case_qosShowQueueStatisticsCommandWithSingleInterface():
    # TODO: Use vtysh communication library.
    out = ops1(format('show interface {p1} queues'))
    assert 'Q0' in out
    assert 'Q1' in out
    assert 'Q2' in out
    assert 'Q3' in out
    assert 'Q4' in out
    assert 'Q5' in out
    assert 'Q6' in out
    assert 'Q7' in out

def case_qosShowQueueStatisticsCommandWithAllInterfaces():
    # TODO: Use vtysh communication library.
    out = ops1(format('show interface queues'))
    assert 'Q0' in out
    assert 'Q1' in out
    assert 'Q2' in out
    assert 'Q3' in out
    assert 'Q4' in out
    assert 'Q5' in out
    assert 'Q6' in out
    assert 'Q7' in out

def case_qosScheduleProfileShowCommand():
    out = ops1.libs.vtysh.show_qos_schedule_profile('profile1')
    assert out['0']['queue_num'] == '0'
    assert out['0']['algorithm'] == 'dwrr'
    assert out['0']['weight'] == '1'

def case_qosScheduleProfileShowCommandWithIllegalName():
    # TODO: Use vtysh communication library.
    out = ops1(format('show qos schedule-profile '
                         'NameThatIsLongerThan64Charactersssssssssssssss'
                         'sssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('show qos schedule-profile '
                         'NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosScheduleProfileShowCommandShowsAllProfiles():
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['IncompleteProfile']['profile_status'] == 'incomplete'
    assert out['profile1']['profile_status'] == 'complete'
    assert out['default']['profile_status'] == 'applied'

def case_qosScheduleProfileShowCommandFactoryDefault():
    out = ops1.libs.vtysh.show_qos_schedule_profile('factory-default')
    assert out['0']['queue_num'] == '0'
    assert out['0']['algorithm'] == 'dwrr'
    assert out['0']['weight'] == '1'

def case_qosScheduleProfileShowCommandWithNonExistentProfile():
    # TODO: Use vtysh communication library.
    out = ops1(format('show qos schedule-profile NonExistent'))
    assert 'does not exist' in out

def case_qosTrustGlobalShowRunningConfigWithDefault():
    with ops1.libs.vtysh.ConfigInterface(format('{p1}')) as ctx:
        ctx.no_qos_trust()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('none')

    # TODO: Use vtysh communication library.
    out = ops1('show running-config')
    assert 'trust' not in out

def case_qosTrustGlobalShow():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('dscp')

    out = ops1.libs.vtysh.show_qos_trust()
    assert out['trust'] == 'dscp'

    out = ops1.libs.vtysh.show_qos_trust('default')
    assert out['trust'] == 'none'

def case_qosTrustPortShowRunningConfigWithDefault():
    with ops1.libs.vtysh.ConfigInterface(format('{p1}')) as ctx:
        ctx.qos_trust('none')

    # TODO: Use vtysh communication library.
    out = ops1('show running-config')
    assert 'qos trust' in out
    out = ops1(format('show running-config interface {p1}'))
    assert 'qos trust' in out
    out = ops1(format('show interface {p1}'))
    assert 'qos trust none' in out

def case_qosTrustPortShowRunningConfigWithNonDefault():
    with ops1.libs.vtysh.ConfigInterface(format('{p1}')) as ctx:
        ctx.qos_trust('dscp')

    # TODO: Use vtysh communication library.
    out = ops1('show running-config')
    assert 'qos trust dscp' in out
    out = ops1(format('show running-config interface {p1}'))
    assert 'qos trust dscp' in out
    out = ops1(format('show interface {p1}'))
    assert 'qos trust dscp' in out

def test_qos_ft(topology, setup):
    setUp_qosApplyGlobal()

    case_qosCosMapShowRunningConfigWithDefault()
    case_qosCosMapShow()

    case_qosCosPortShowRunningConfig()
    case_qosCosPortShowRunningConfigInterface()
    case_qosCosPortShowInterface()

    case_qosDscpMapShowRunningConfigWithDefault()
    case_qosDscpMapShow()

    case_qosDscpPortShow()

    case_qosQueueProfileShowCommand()
    case_qosQueueProfileShowCommandWithIllegalName()
    case_qosQueueProfileShowCommandShowsAllProfiles()
    case_qosQueueProfileShowCommandFactoryDefault()
    case_qosQueueProfileShowCommandWithNonExistentProfile()

    case_qosShowQueueStatisticsCommandWithSingleInterface()
    case_qosShowQueueStatisticsCommandWithAllInterfaces()

    case_qosScheduleProfileShowCommand()
    case_qosScheduleProfileShowCommandWithIllegalName()
    case_qosScheduleProfileShowCommandShowsAllProfiles()
    case_qosScheduleProfileShowCommandFactoryDefault()
    case_qosScheduleProfileShowCommandWithNonExistentProfile()

    case_qosTrustGlobalShowRunningConfigWithDefault()
    case_qosTrustGlobalShow()

    case_qosTrustPortShowRunningConfigWithDefault()
    case_qosTrustPortShowRunningConfigWithNonDefault()
