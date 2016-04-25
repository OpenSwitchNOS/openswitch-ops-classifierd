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

    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('vlan 1'))

    ops1(format('interface {p1}'))
    ops1(format('no routing'))
    ops1(format('vlan access 1'))
    ops1(format('vlan trunk allowed 1'))

    ops1(format('end'))

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
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('apply qos queue-profile '
                   'default schedule-profile default'))

    ops1(format('no qos queue-profile p1'))
    ops1(format('qos queue-profile p1'))
    ops1(format('map queue 4 local-priority 3'))
    ops1(format('map queue 5 local-priority 2'))
    ops1(format('map queue 6 local-priority 1'))
    ops1(format('map queue 7 local-priority 0'))
    ops1(format('map queue 0 local-priority 7'))
    ops1(format('map queue 1 local-priority 6'))
    ops1(format('map queue 2 local-priority 5'))
    ops1(format('map queue 3 local-priority 4'))
    ops1(format('exit'))

    ops1(format('no qos schedule-profile p1'))
    ops1(format('qos schedule-profile p1'))
    ops1(format('dwrr queue 4 weight 40'))
    ops1(format('dwrr queue 5 weight 50'))
    ops1(format('dwrr queue 6 weight 60'))
    ops1(format('dwrr queue 7 weight 70'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))

def setUp_qosApplyPort():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('interface {p1}'))
    ops1(format('no lag 10'))
    ops1(format('no apply qos schedule-profile'))
    ops1(format('exit'))

    ops1(format('interface lag 10'))
    ops1(format('no apply qos schedule-profile'))
    ops1(format('exit'))

    ops1(format('no qos schedule-profile p1'))
    ops1(format('qos schedule-profile p1'))
    ops1(format('dwrr queue 4 weight 40'))
    ops1(format('dwrr queue 5 weight 50'))
    ops1(format('dwrr queue 6 weight 60'))
    ops1(format('dwrr queue 7 weight 70'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))

    ops1(format('end'))
    ops1(format('configure terminal'))

def setUp_qosCosMap():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('no qos cos-map 7'))

def setup_qosCosPort():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('no qos cos'))

    ops1(format('interface {p1}'))
    ops1(format('no lag 10'))
    ops1(format('no qos trust'))
    ops1(format('no qos cos'))

    ops1(format('interface lag 10'))
    ops1(format('no qos trust'))
    ops1(format('no qos cos'))

    ops1(format('end'))
    ops1(format('configure terminal'))

def setUp_qosDscpMap():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('no qos dscp-map 38'))

def setUp_qosDscpPort():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('no qos dscp'))

    ops1(format('interface {p1}'))
    ops1(format('no lag 10'))
    ops1(format('no qos trust'))
    ops1(format('no qos dscp'))

    ops1(format('interface lag 10'))
    ops1(format('no qos trust'))
    ops1(format('no qos dscp'))

    ops1(format('end'))
    ops1(format('configure terminal'))

def setUp_qosQueueProfile():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('apply qos queue-profile default '
                   'schedule-profile default'))

    ops1(format('no qos queue-profile p1'))
    ops1(format('no qos queue-profile p2'))

def setUp_qosQueueStatistics():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('no interface lag 10'))

def setUp_qosScheduleProfile():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('apply qos queue-profile default '
                   'schedule-profile default'))

    ops1(format('no qos schedule-profile p1'))
    ops1(format('no qos schedule-profile p2'))

def setUp_qosTrustGlobal():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('no qos trust'))

def setUp_qosTrustPort():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('no qos trust'))

    ops1(format('interface {p1}'))
    ops1(format('no lag 10'))
    ops1(format('no qos trust'))

    ops1(format('interface lag 10'))
    ops1(format('no qos trust'))

    ops1(format('end'))
    ops1(format('configure terminal'))

def get_local_priority_range():
    printed_show_output = ops1(format('do show qos cos-map default'))

    min_local_priority = sys.maxsize
    max_local_priority = -1
    lines = printed_show_output.split('\n')
    for line in lines:
        if line[0].isdigit():
            line_split = line.split(' ')

            local_priority = -1
            ints_found_count = 0
            for split in line_split:
                if split.isdigit():
                    ints_found_count += 1
                if ints_found_count == 2:
                    local_priority = int(split)
                    break

            if local_priority > max_local_priority:
                max_local_priority = local_priority

            if local_priority < min_local_priority:
                min_local_priority = local_priority

    local_priority_range = [min_local_priority, max_local_priority]
    return local_priority_range

def case_qosCosMapShowRunningConfigWithDefault():
    setUp_qosCosMap()
    ops1(format('qos cos-map 1 local-priority 0 '
                   'color green name "Background"'))
    out = ops1(format('do show running-config'))
    assert 'qos' not in out
    assert 'cos-map' not in out
    assert 'code_point' not in out
    assert 'local_priority' not in out
    assert 'color' not in out
    assert 'name' not in out

def case_qosCosMapShowCommand():
    setUp_qosCosMap()
    ops1(format('qos cos-map 7 local-priority 2 '
                   'color yellow name MyName2'))
    out = ops1(format('do show qos cos-map'))
    assert '7          2              yellow  MyName2' in out

def case_qosCosMapShowCommandWithDefault():
    setUp_qosCosMap()
    ops1(format('qos cos-map 7 local-priority 2 '
                   'color yellow name MyName2'))
    out = ops1(format('do show qos cos-map default'))
    assert '7          7              green   Network_Control' in out
    setUp_qosCosMap()

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
    setUp_qosDscpMap()
    ops1(format('qos dscp-map 38 local-priority 4 '
                   'cos 4 color red name AF43'))
    out = ops1(format('do show running-config'))
    assert 'qos' not in out
    assert 'dscp-map' not in out
    assert 'code_point' not in out
    assert 'local_priority' not in out
    assert 'cos' not in out
    assert 'color' not in out
    assert 'name' not in out

def case_qosDscpMapShowCommand():
    setUp_qosDscpMap()
    ops1(format('qos dscp-map 38 local-priority 2 '
                   'color yellow name MyName2'))
    out = ops1(format('do show qos dscp-map'))
    assert '38         2              yellow  MyName2' in out

def case_qosDscpMapShowCommandWithDefault():
    setUp_qosDscpMap()
    ops1(format('qos dscp-map 38 local-priority 2 '
                   'color yellow name MyName2'))
    out = ops1(format('do show qos dscp-map default'))
    assert '38         4              red     AF43' in out
    setUp_qosDscpMap()

def case_qosDscpPortShowRunningConfig():
    setUp_qosDscpPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos dscp 1'))
    out = ops1(format('do show running-config'))
    assert 'qos dscp 1' in out

def case_qosDscpPortShowRunningConfigInterface():
    setUp_qosDscpPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos dscp 1'))
    out = ops1(format('do show running-config interface {p1}'))
    assert 'qos dscp 1' in out

def case_qosDscpPortShowInterface():
    setUp_qosDscpPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos dscp 1'))
    out = ops1(format('do show interface {p1}'))
    assert 'override' in out
    setUp_qosDscpPort()

def case_qosQueueProfileShowCommand():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    ops1(format('name queue 1 QueueName'))
    out = ops1(format('do show qos queue-profile p1'))
    assert 'QueueName' in out

def case_qosQueueProfileShowCommandWithIllegalName():
    setUp_qosQueueProfile()
    out = ops1(format('do show qos queue-profile '
                         'NameThatIsLongerThan64Characterssssssssssssssss'
                         'ssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('do show qos queue-profile '
                         'NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosQueueProfileShowCommandShowsAllProfiles():
    setUp_qosQueueProfile()

    # Create a 'complete' profile.
    ops1(format('qos queue-profile p1'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 0 local-priority 1'))
    ops1(format('map queue 0 local-priority 2'))
    ops1(format('map queue 0 local-priority 3'))
    ops1(format('map queue 0 local-priority 4'))
    ops1(format('map queue 0 local-priority 5'))
    ops1(format('map queue 0 local-priority 6'))
    ops1(format('map queue 0 local-priority 7'))
    ops1(format('exit'))

    # Create an 'incomplete' profile.
    ops1(format('qos queue-profile p2'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('exit'))

    out = ops1(format('do show qos queue-profile'))
    assert 'incomplete     p2' in out
    assert 'complete       p1' in out
    assert 'complete       factory-default' in out
    assert 'applied        default' in out

def case_qosQueueProfileShowCommandFactoryDefault():
    setUp_qosQueueProfile()
    out = ops1(format('do show qos queue-profile factory-default'))
    assert 'queue_num' in out

def case_qosQueueProfileShowCommandWithNonExistentProfile():
    setUp_qosQueueProfile()
    out = ops1(format('do show qos queue-profile NonExistent'))
    assert 'does not exist' in out
    setUp_qosQueueProfile()

def case_qosShowQueueStatisticsCommandWithSingleInterface():
    setUp_qosQueueStatistics()
    out = ops1(format('do show interface {p1} queues'))
    assert 'Q0' in out
    assert 'Q1' in out
    assert 'Q2' in out
    assert 'Q3' in out
    assert 'Q4' in out
    assert 'Q5' in out
    assert 'Q6' in out
    assert 'Q7' in out

def case_qosShowQueueStatisticsCommandWithAllInterfaces():
    setUp_qosQueueStatistics()
    out = ops1(format('do show interface queues'))
    assert 'Q0' in out
    assert 'Q1' in out
    assert 'Q2' in out
    assert 'Q3' in out
    assert 'Q4' in out
    assert 'Q5' in out
    assert 'Q6' in out
    assert 'Q7' in out
    setUp_qosQueueStatistics()

def case_qosScheduleProfileShowCommand():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    ops1(format('strict queue 1'))
    out = ops1(format('do show qos schedule-profile p1'))
    assert 'strict' in out
    assert '1' in out

def case_qosScheduleProfileShowCommandWithIllegalName():
    setUp_qosScheduleProfile()
    out = ops1(format('do show qos schedule-profile '
                         'NameThatIsLongerThan64Charactersssssssssssssss'
                         'sssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('do show qos schedule-profile '
                         'NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosScheduleProfileShowCommandShowsAllProfiles():
    setUp_qosScheduleProfile()

    # Create a 'complete' profile.
    ops1(format('qos schedule-profile p1'))
    ops1(format('strict queue 0'))
    ops1(format('exit'))

    # Create an 'incomplete' profile.
    ops1(format('qos schedule-profile p2'))
    ops1(format('exit'))

    out = ops1(format('do show qos schedule-profile'))
    assert 'incomplete     p2' in out
    assert 'complete       p1' in out
    assert 'complete       factory-default' in out
    assert 'applied        default' in out

def case_qosScheduleProfileShowCommandFactoryDefault():
    setUp_qosScheduleProfile()
    out = ops1(format('do show qos schedule-profile factory-default'))
    assert 'queue_num' in out

def case_qosScheduleProfileShowCommandWithNonExistentProfile():
    setUp_qosScheduleProfile()
    out = ops1(format('do show qos schedule-profile NonExistent'))
    assert 'does not exist' in out
    setUp_qosScheduleProfile()

def case_qosTrustGlobalShowRunningConfigWithDefault():
    setUp_qosTrustGlobal()
    ops1(format('qos trust none'))
    out = ops1(format('do show running-config'))
    assert 'qos' not in out
    assert 'trust' not in out

def case_qosTrustGlobalShowCommand():
    setUp_qosTrustGlobal()
    ops1(format('qos trust dscp'))
    out = ops1(format('do show qos trust'))
    assert 'qos trust dscp' in out
    setUp_qosTrustGlobal()

def case_qosTrustGlobalShowCommandWithDefault():
    setUp_qosTrustGlobal()
    ops1(format('qos trust dscp'))
    out = ops1(format('do show qos trust default'))
    assert 'qos trust none' in out
    setUp_qosTrustGlobal()

def case_qosTrustPortShowRunningConfigWithDefault():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    out = ops1(format('do show running-config'))
    assert 'qos' in out
    assert 'trust' in out

def case_qosTrustPortShowRunningConfigWithNonDefault():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust dscp'))
    out = ops1(format('do show running-config'))
    assert 'qos trust dscp' in out

def case_qosTrustPortShowRunningConfigInterfaceWithDefault():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    out = ops1(format('do show running-config interface {p1}'))
    assert 'qos trust' in out

def case_qosTrustPortShowRunningConfigInterfaceWithNonDefault():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust dscp'))
    out = ops1(format('do show running-config interface {p1}'))
    assert 'qos trust dscp' in out

def case_qosTrustPortShowInterfaceWithDefault():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    out = ops1(format('do show interface {p1}'))
    assert 'qos trust none' in out

def case_qosTrustPortShowInterfaceWithNonDefault():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust dscp'))
    out = ops1(format('do show interface {p1}'))
    assert 'qos trust dscp' in out
    setUp_qosTrustPort()

def test_qos_ft(topology, setup):
    case_qosCosMapShowRunningConfigWithDefault()
    case_qosCosMapShowCommand()
    case_qosCosMapShowCommandWithDefault()

    case_qosCosPortShowRunningConfig()
    case_qosCosPortShowRunningConfigInterface()
    case_qosCosPortShowInterface()

    case_qosDscpMapShowRunningConfigWithDefault()
    case_qosDscpMapShowCommand()
    case_qosDscpMapShowCommandWithDefault()

    case_qosDscpPortShowRunningConfig()
    case_qosDscpPortShowRunningConfigInterface()
    case_qosDscpPortShowInterface()

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
    case_qosTrustGlobalShowCommand()
    case_qosTrustGlobalShowCommandWithDefault()

    case_qosTrustPortShowRunningConfigWithDefault()
    case_qosTrustPortShowRunningConfigWithNonDefault()
    case_qosTrustPortShowRunningConfigInterfaceWithDefault()
    case_qosTrustPortShowRunningConfigInterfaceWithNonDefault()
    case_qosTrustPortShowInterfaceWithDefault()
    case_qosTrustPortShowInterfaceWithNonDefault()
