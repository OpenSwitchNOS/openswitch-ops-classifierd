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

    ops1(format('no qos trust'))

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

    ops1(format('no qos trust'))

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

def case_qosApplyGlobalCommand():
    setUp_qosApplyGlobal()
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    out = ops1(format('do show qos queue-profile'))
    assert 'applied        p1' in out
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        p1' in out

def case_qosApplyGlobalCommandWithDuplicateQueueProfileQueue():
    setUp_qosApplyGlobal()
    ops1(format('qos queue-profile p1'))
    ops1(format('map queue 0 local-priority 7'))
    ops1(format('map queue 1 local-priority 7'))
    ops1(format('exit'))
    out = ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    assert 'assigned more than once' in out

def case_qosApplyGlobalCommandWithMissingQueueProfileQueue():
    setUp_qosApplyGlobal()
    ops1(format('qos queue-profile p1'))
    ops1(format('no map queue 7'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('exit'))
    out = ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    assert 'cannot contain different queues' in out

def case_qosApplyGlobalCommandWithMissingScheduleProfileQueue():
    setUp_qosApplyGlobal()
    ops1(format('qos schedule-profile p1'))
    ops1(format('no dwrr queue 7'))
    ops1(format('exit'))
    out = ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    assert 'cannot contain different queues' in out

def case_qosApplyGlobalCommandWithIllegalQueueProfile():
    setUp_qosApplyGlobal()
    out = ops1(format('apply qos queue-profile p&^%$1 '
                         'schedule-profile p1'))
    assert 'allowed' in out

def case_qosApplyGlobalCommandWithNullQueueProfile():
    setUp_qosApplyGlobal()
    out = ops1(format('apply qos queue-profile '
                         'schedule-profile p1'))
    assert 'Unknown command' in out

def case_qosApplyGlobalCommandWithMissingQueueProfile():
    setUp_qosApplyGlobal()
    out = ops1(format('apply qos queue-profile missing '
                         'schedule-profile p1'))
    assert 'does not exist' in out

def case_qosApplyGlobalCommandWithIllegalScheduleProfile():
    setUp_qosApplyGlobal()
    out = ops1(format('apply qos queue-profile p1 '
                         'schedule-profile p&^%$1 '))
    assert 'allowed' in out

def case_qosApplyGlobalCommandWithNullScheduleProfile():
    setUp_qosApplyGlobal()
    out = ops1(format('apply qos queue-profile p1 schedule-profile'))
    assert 'incomplete' in out

def case_qosApplyGlobalCommandWithMissingScheduleProfile():
    setUp_qosApplyGlobal()
    out = ops1(format('apply qos queue-profile p1 '
                         'schedule-profile missing'))
    assert 'does not exist' in out

def case_qosApplyGlobalCommandWithStrictScheduleProfile():
    setUp_qosApplyGlobal()
    ops1(format('apply qos queue-profile default '
                   'schedule-profile strict'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        strict' in out

def case_qosApplyGlobalCommandWithAllStrict():
    setUp_qosApplyGlobal()
    ops1(format('qos schedule-profile p1'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('strict queue 0'))
    ops1(format('strict queue 1'))
    ops1(format('strict queue 2'))
    ops1(format('strict queue 3'))
    ops1(format('exit'))
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        p1' in out

def case_qosApplyGlobalCommandWithAllWrr():
    setUp_qosApplyGlobal()
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
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        p1' in out

def case_qosApplyGlobalCommandWithAllWrrWithMaxStrict():
    setUp_qosApplyGlobal()
    ops1(format('qos schedule-profile p1'))
    ops1(format('dwrr queue 4 weight 40'))
    ops1(format('dwrr queue 5 weight 50'))
    ops1(format('dwrr queue 6 weight 60'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        p1' in out

def case_qosApplyGlobalCommandWithHigherStrictLowerWrr():
    setUp_qosApplyGlobal()
    ops1(format('qos schedule-profile p1'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))
    out = ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    assert 'must have the same algorithm assigned to each queue' in out

def case_qosApplyGlobalCommandWithLowerStrictHigherWrr():
    setUp_qosApplyGlobal()
    ops1(format('qos schedule-profile p1'))
    ops1(format('dwrr queue 4 weight 40'))
    ops1(format('dwrr queue 5 weight 50'))
    ops1(format('dwrr queue 6 weight 60'))
    ops1(format('dwrr queue 7 weight 70'))
    ops1(format('strict queue 0'))
    ops1(format('strict queue 1'))
    ops1(format('strict queue 2'))
    ops1(format('strict queue 3'))
    ops1(format('exit'))
    out = ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    assert 'must have the same algorithm assigned to each queue' in out

def case_qosApplyGlobalCommandAndThenRestoreDefaultQueueProfile():
    setUp_qosApplyGlobal()
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    ops1(format('qos queue-profile default'))
    ops1(format('name queue 0 QueueName'))
    out = ops1(format('do show qos queue-profile default'))
    assert 'QueueName' in out
    ops1(format('no qos queue-profile default'))
    out = ops1(format('do show qos queue-profile default'))
    assert 'QueueName' not in out

def case_qosApplyGlobalCommandAndThenRestoreDefaultScheduleProfile():
    setUp_qosApplyGlobal()
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))
    ops1(format('qos schedule-profile default'))
    ops1(format('strict queue 0'))
    out = ops1(format('do show qos schedule-profile default'))
    assert '0         strict' in out
    ops1(format('no qos schedule-profile default'))
    out = ops1(format('do show qos schedule-profile default'))
    assert '0         strict' not in out

def case_qosApplyGlobalCommandWithPortScheduleProfileWithDifferentQueues():
    # Create profiles with just one queue.
    ops1(format('no qos queue-profile p2'))
    ops1(format('qos queue-profile p2'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 0 local-priority 1'))
    ops1(format('map queue 0 local-priority 2'))
    ops1(format('map queue 0 local-priority 3'))
    ops1(format('map queue 0 local-priority 4'))
    ops1(format('map queue 0 local-priority 5'))
    ops1(format('map queue 0 local-priority 6'))
    ops1(format('map queue 0 local-priority 7'))
    ops1(format('exit'))

    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 0'))
    ops1(format('exit'))

    # Apply the one-queue profiles to system and port.
    ops1(format('apply qos queue-profile p2 schedule-profile p2'))
    ops1(format('interface {p1}'))
    ops1(format('apply qos schedule-profile p2'))
    ops1(format('exit'))

    # Globally applying the default profiles should fail, since they
    # have 8 queues rather than 1 queue.
    out = ops1(format('apply qos queue-profile ' + \
                        'default schedule-profile default'))
    assert 'schedule profile applied on port' in out
    assert 'cannot contain different queues' in out

    # Un-apply the one-queue profiles.
    ops1(format('interface {p1}'))
    ops1(format('no apply qos schedule-profile'))
    ops1(format('exit'))
    ops1(format('apply qos queue-profile default ' + \
                   'schedule-profile default'))

def case_qosApplyGlobalCommandWithPortScheduleProfileStrict():
    # Create profiles with just one queue.
    ops1(format('no qos queue-profile p2'))
    ops1(format('qos queue-profile p2'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 0 local-priority 1'))
    ops1(format('map queue 0 local-priority 2'))
    ops1(format('map queue 0 local-priority 3'))
    ops1(format('map queue 0 local-priority 4'))
    ops1(format('map queue 0 local-priority 5'))
    ops1(format('map queue 0 local-priority 6'))
    ops1(format('map queue 0 local-priority 7'))
    ops1(format('exit'))

    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 0'))
    ops1(format('exit'))

    # Apply the one-queue profiles to system.
    ops1(format('apply qos queue-profile p2 schedule-profile p2'))

    # Apply strict to port.
    ops1(format('interface {p1}'))
    ops1(format('apply qos schedule-profile strict'))
    ops1(format('exit'))

    # Globally applying the default profiles should succeed, since the
    # port schedule profile is just strict.
    out = ops1(format('apply qos queue-profile ' + \
                        'default schedule-profile default'))
    out = ops1(format('do show qos queue-profile'))
    assert 'applied        default' in out
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        default' in out

    # Un-apply the one-queue profiles.
    ops1(format('interface {p1}'))
    ops1(format('no apply qos schedule-profile'))
    ops1(format('exit'))
    ops1(format('apply qos queue-profile default ' + \
                   'schedule-profile default'))

    setUp_qosApplyGlobal()

def case_qosApplyPortCommand():
    setUp_qosApplyPort()
    ops1(format('interface {p1}'))
    ops1(format('apply qos schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        p1' in out

def case_qosApplyPortCommandWithMissingScheduleProfileQueue():
    setUp_qosApplyPort()
    ops1(format('qos schedule-profile p1'))
    ops1(format('no dwrr queue 7'))
    ops1(format('exit'))
    ops1(format('interface {p1}'))
    out = ops1(format('apply qos schedule-profile p1'))
    assert 'cannot contain different queues' in out

def case_qosApplyPortCommandWithIllegalScheduleProfile():
    setUp_qosApplyPort()
    ops1(format('interface {p1}'))
    out = ops1(format('apply qos schedule-profile p&^%$1 '))
    assert 'allowed' in out

def case_qosApplyPortCommandWithNullScheduleProfile():
    setUp_qosApplyPort()
    ops1(format('interface {p1}'))
    out = ops1(format('apply qos schedule-profile'))
    assert 'incomplete' in out

def case_qosApplyPortCommandWithInterfaceInLag():
    setUp_qosApplyPort()
    ops1(format('interface {p1}'))
    ops1(format('lag 10'))
    out = ops1(format('apply qos schedule-profile p1'))
    assert 'cannot' in out

def case_qosApplyPortCommandWithMissingScheduleProfile():
    setUp_qosApplyPort()
    ops1(format('interface {p1}'))
    out = ops1(format('apply qos schedule-profile missing'))
    assert 'does not exist' in out

def case_qosApplyPortCommandWithStrictScheduleProfile():
    setUp_qosApplyPort()
    ops1(format('interface {p1}'))
    ops1(format('apply qos schedule-profile strict'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        strict' in out

def case_qosApplyPortCommandWithAllStrict():
    setUp_qosApplyPort()
    ops1(format('qos schedule-profile p1'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('strict queue 0'))
    ops1(format('strict queue 1'))
    ops1(format('strict queue 2'))
    ops1(format('strict queue 3'))
    ops1(format('exit'))
    ops1(format('interface {p1}'))
    ops1(format('apply qos schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        p1' in out

def case_qosApplyPortCommandWithAllWrr():
    setUp_qosApplyPort()
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
    ops1(format('interface {p1}'))
    ops1(format('apply qos schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        p1' in out

def case_qosApplyPortCommandWithAllWrrWithMaxStrict():
    setUp_qosApplyPort()
    ops1(format('qos schedule-profile p1'))
    ops1(format('dwrr queue 4 weight 40'))
    ops1(format('dwrr queue 5 weight 50'))
    ops1(format('dwrr queue 6 weight 60'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))
    ops1(format('interface {p1}'))
    ops1(format('apply qos schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'applied        p1' in out

def case_qosApplyPortCommandWithHigherStrictLowerWrr():
    setUp_qosApplyPort()
    ops1(format('qos schedule-profile p1'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))
    ops1(format('interface {p1}'))
    out = ops1(format('apply qos schedule-profile p1'))
    assert 'must have the same algorithm assigned to each queue' in out

def case_qosApplyPortCommandWithLowerStrictHigherWrr():
    setUp_qosApplyPort()
    ops1(format('qos schedule-profile p1'))
    ops1(format('dwrr queue 4 weight 40'))
    ops1(format('dwrr queue 5 weight 50'))
    ops1(format('dwrr queue 6 weight 60'))
    ops1(format('dwrr queue 7 weight 70'))
    ops1(format('strict queue 0'))
    ops1(format('strict queue 1'))
    ops1(format('strict queue 2'))
    ops1(format('strict queue 3'))
    ops1(format('exit'))
    ops1(format('interface {p1}'))
    out = ops1(format('apply qos schedule-profile p1'))
    assert 'must have the same algorithm assigned to each queue' in out

def case_qosApplyPortNoCommand():
    setUp_qosApplyPort()
    ops1(format('interface {p1}'))
    ops1(format('apply schedule-profile p1'))
    ops1(format('no apply qos schedule-profile'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'complete       p1' in out

def case_qosApplyPortNoCommandWithInterfaceInLag():
    setUp_qosApplyPort()
    ops1(format('interface {p1}'))
    ops1(format('lag 10'))
    out = ops1(format('no apply qos schedule-profile'))
    assert 'cannot' in out
    setUp_qosApplyPort()

def case_qosCosMapCommand():
    setUp_qosCosMap()
    ops1(format('qos cos-map 7 local-priority 1 '
                   'color red name MyName1'))
    ops1(format('qos cos-map 7 local-priority 2 '
                   'color yellow name MyName2'))
    out = ops1(format('do show qos cos-map'))
    assert '7          2              yellow  MyName2' in out

def case_qosCosMapCommandWithIllegalCodePoint():
    setUp_qosCosMap()
    out = ops1(format('qos cos-map -1 local-priority 2 '
                         'color yellow name MyName2'))
    assert 'Unknown command' in out
    out = ops1(format('qos cos-map 8 local-priority 2 '
                         'color yellow name MyName2'))
    assert 'Unknown command' in out

def case_qosCosMapCommandWithNullCodePoint():
    setUp_qosCosMap()
    out = ops1(format('qos cos-map local-priority 2 '
                         'color yellow name MyName2'))
    assert 'Unknown command' in out

def case_qosCosMapCommandWithIllegalLocalPriority():
    setUp_qosCosMap()
    local_priority_range = get_local_priority_range()

    out = ops1(format('qos cos-map 7 local-priority ' +
                         str(local_priority_range[0] - 1) +
                         ' color yellow name MyName2'))
    assert 'Unknown command' in out
    out = ops1(format('qos cos-map 7 local-priority ' +
                         str(local_priority_range[1] + 1) +
                         ' color yellow name MyName2'))
    assert 'Unknown command' in out

def case_qosCosMapCommandWithNullLocalPriority():
    setUp_qosCosMap()
    out = ops1(format('qos cos-map 7 color yellow name MyName2'))
    assert 'Unknown command' in out

def case_qosCosMapCommandWithIllegalColor():
    setUp_qosCosMap()
    out = ops1(format('qos cos-map 7 local-priority 2 '
                         'name MyName2 color illegal'))
    assert 'Unknown command' in out

def case_qosCosMapCommandWithNullColor():
    setUp_qosCosMap()
    out = ops1(format('qos cos-map 7 local-priority 2 name MyName2'))
    out = ops1(format('do show qos cos-map'))
    assert '7          2              green   MyName2' in out

    out = ops1(format('qos cos-map 7 local-priority 2 '
                         'name MyName2 color'))
    assert 'incomplete.' in out

def case_qosCosMapCommandWithIllegalName():
    setUp_qosCosMap()
    out = ops1(format('qos cos-map 7 local-priority 2 color yellow '
                         'name NameThatIsLongerThan64Characterssssssss'
                         'ssssssssssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('qos cos-map 7 local-priority 2 color yellow '
                         'name NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosCosMapCommandWithNullName():
    setUp_qosCosMap()
    out = ops1(format('qos cos-map 7 local-priority 2 color yellow'))
    out = ops1(format('do show qos cos-map'))
    assert '7          2              yellow' in out

    out = ops1(format('qos cos-map 7 local-priority 2 '
                         'color yellow name'))
    assert 'incomplete.' in out

def case_qosCosMapNoCommand():
    setUp_qosCosMap()
    ops1(format('qos cos-map 7 local-priority 2 '
                   'color yellow name MyName2'))
    ops1(format('no qos cos-map 7'))
    out = ops1(format('do show qos cos-map'))
    assert '7          7              green   Network_Control' in out

def case_qosCosPortCommand():
    # This command is not supported in dill.
    return
    setup_qosCosPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos cos 1'))
    out = ops1(format('do show running-config interface {p1}'))
    assert 'override 1' in out

def case_qosCosPortCommandWithSystemTrustNoneAndPortTrustCos():
    # This command is not supported in dill.
    return
    setUp_qosCosPort()
    ops1(format('qos trust none'))
    ops1(format('interface {p1}'))
    ops1(format('qos trust cos'))
    out = ops1(format('qos cos 1'))
    assert 'only allowed' in out

def case_qosCosPortCommandWithSystemTrustNoneAndPortTrustMissing():
    # This command is not supported in dill.
    return
    setUp_qosCosPort()
    ops1(format('qos trust none'))
    ops1(format('interface {p1}'))
    ops1(format('no qos trust'))
    out = ops1(format('qos cos 1'))
    out = ops1(format('do show interface {p1}'))
    assert 'override 1' in out

def case_qosCosPortCommandWithSystemTrustCosAndPortTrustNone():
    # This command is not supported in dill.
    return
    setUp_qosCosPort()
    ops1(format('qos trust cos'))
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    out = ops1(format('qos cos 1'))
    out = ops1(format('do show interface {p1}'))
    assert 'override 1' in out

def case_qosCosPortCommandWithSystemTrustCosAndPortTrustMissing():
    # This command is not supported in dill.
    return
    setUp_qosCosPort()
    ops1(format('qos trust cos'))
    ops1(format('interface {p1}'))
    ops1(format('no qos trust'))
    out = ops1(format('qos cos 1'))
    assert 'only allowed' in out

def case_qosCosPortCommandWithIllegalQosCos():
    # This command is not supported in dill.
    return
    setup_qosCosPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    out = ops1(format('qos cos 8'))
    assert 'Unknown command' in out

def case_qosCosPortCommandWithNullQosCos():
    # This command is not supported in dill.
    return
    setup_qosCosPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    out = ops1(format('qos cos'))
    assert 'Command incomplete' in out

def case_qosCosPortCommandWithInterfaceInLag():
    # This command is not supported in dill.
    return
    setup_qosCosPort()
    ops1(format('interface {p1}'))
    ops1(format('lag 10'))
    ops1(format('qos trust none'))
    out = ops1(format('qos cos 1'))
    assert 'cannot' in out

def case_qosCosPortNoCommand():
    # This command is not supported in dill.
    return
    setup_qosCosPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos cos 1'))
    out = ops1(format('do show running-config interface {p1}'))
    assert 'override' in out
    ops1(format('no qos cos'))
    out = ops1(format('do show running-config interface {p1}'))
    assert 'override' not in out

def case_qosCosPortNoCommandWithInterfaceInLag():
    # This command is not supported in dill.
    return
    setup_qosCosPort()
    ops1(format('interface {p1}'))
    ops1(format('lag 10'))
    ops1(format('qos trust none'))
    out = ops1(format('no qos cos'))
    assert 'cannot' in out

def case_qosDscpMapCommand():
    setUp_qosDscpMap()
    ops1(format('qos dscp-map 38 local-priority 1 '
                   'color green name MyName1'))
    ops1(format('qos dscp-map 38 local-priority 2 '
                'color yellow name MyName2'))
    out = ops1(format('do show qos dscp-map'))
    assert '38         2              yellow  MyName2' in out

def case_qosDscpMapCommandWithIllegalCodePoint():
    setUp_qosDscpMap()
    out = ops1(format('qos dscp-map -1 local-priority 2 '
                         'cos 3 color yellow name MyName2'))
    assert 'Unknown command' in out
    out = ops1(format('qos dscp-map 64 local-priority 2 '
                         'cos 3 color yellow name MyName2'))
    assert 'Unknown command' in out

def case_qosDscpMapCommandWithNullCodePoint():
    setUp_qosDscpMap()
    out = ops1(format('qos dscp-map local-priority 2 '
                         'cos 3 color yellow name MyName2'))
    assert 'Unknown command' in out

def case_qosDscpMapCommandWithIllegalLocalPriority():
    setUp_qosDscpMap()
    local_priority_range = get_local_priority_range()

    out = ops1(format('qos dscp-map 38 local-priority ' +
                         str(local_priority_range[0] - 1) +
                         ' color yellow name MyName2'))
    assert 'Unknown command' in out
    out = ops1(format('qos dscp-map 38 local-priority ' +
                         str(local_priority_range[1] + 1) +
                         ' color yellow name MyName2'))
    assert 'Unknown command' in out

def case_qosDscpMapCommandWithNullLocalPriority():
    setUp_qosDscpMap()
    out = ops1(format('qos dscp-map 38 cos 3 color yellow name MyName2'))
    assert 'Unknown command' in out

def case_qosDscpMapCommandWithIllegalCos():
    # The cos option is not supported in dill.
    return
    setUp_qosDscpMap()
    out = ops1(format('qos dscp-map 38 local-priority 2 '
                         'cos 8 color yellow name MyName2'))
    assert 'Unknown command' in out

def case_qosDscpMapCommandWithNullCos():
    # The cos option is not supported in dill.
    return
    setUp_qosDscpMap()
    out = ops1(format('qos dscp-map 38 local-priority 2 '
                         'color yellow name MyName2'))
    out = ops1(format('do show running-config'))
    assert 'code_point 38' in out
    assert 'local_priority 2' in out
    assert 'cos <empty>' in out
    assert 'color yellow' in out
    assert 'name MyName2' in out

def case_qosDscpMapCommandWithIllegalColor():
    setUp_qosDscpMap()
    out = ops1(format('qos dscp-map 38 local-priority 2 '
                      'name MyName2 color illegal'))
    assert 'Unknown command' in out

def case_qosDscpMapCommandWithNullColor():
    setUp_qosDscpMap()
    out = ops1(format('qos dscp-map 38 local-priority 2 name MyName2'))
    out = ops1(format('do show qos dscp-map'))
    assert '38         2              green   MyName2 ' in out

    out = ops1(format('qos dscp-map 38 local-priority 2 '
                      'name MyName2 color'))
    assert 'incomplete.' in out

def case_qosDscpMapCommandWithIllegalName():
    setUp_qosDscpMap()
    out = ops1(format('qos dscp-map 38 local-priority 2 color yellow '
                         'name NameThatIsLongerThan64Charactersssssssssss'
                         'sssssssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('qos dscp-map 38 local-priority 2 color yellow '
                         'name NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosDscpMapCommandWithNullName():
    setUp_qosDscpMap()
    out = ops1(format('qos dscp-map 38 local-priority 2 color yellow'))
    out = ops1(format('do show qos dscp-map'))
    assert '38         2              yellow' in out

    out = ops1(format('qos dscp-map 38 local-priority 2 '
                         'color green name'))
    assert 'incomplete.' in out

def case_qosDscpMapNoCommand():
    setUp_qosDscpMap()
    ops1(format('qos dscp-map 38 local-priority 2 '
                   'color yellow name MyName2'))
    ops1(format('no qos dscp-map 38'))
    out = ops1(format('do show qos dscp-map'))
    assert '38         4              red     AF43' in out

def case_qosDscpPortCommand():
    setUp_qosDscpPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos dscp 1'))
    out = ops1(format('do show interface {p1}'))
    assert 'override 1' in out

def case_qosDscpPortCommandWithSystemTrustNoneAndPortTrustDscp():
    setUp_qosDscpPort()
    ops1(format('qos trust none'))
    ops1(format('interface {p1}'))
    ops1(format('qos trust dscp'))
    out = ops1(format('qos dscp 1'))
    assert 'only allowed' in out

def case_qosDscpPortCommandWithSystemTrustNoneAndPortTrustMissing():
    setUp_qosDscpPort()
    ops1(format('qos trust none'))
    ops1(format('interface {p1}'))
    ops1(format('no qos trust'))
    out = ops1(format('qos dscp 1'))
    out = ops1(format('do show interface {p1}'))
    assert 'override 1' in out

def case_qosDscpPortCommandWithSystemTrustDscpAndPortTrustNone():
    setUp_qosDscpPort()
    ops1(format('qos trust dscp'))
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    out = ops1(format('qos dscp 1'))
    out = ops1(format('do show interface {p1}'))
    assert 'override 1' in out

def case_qosDscpPortCommandWithSystemTrustDscpAndPortTrustMissing():
    setUp_qosDscpPort()
    ops1(format('qos trust dscp'))
    ops1(format('interface {p1}'))
    ops1(format('no qos trust'))
    out = ops1(format('qos dscp 1'))
    assert 'only allowed' in out

def case_qosDscpPortCommandWithIllegalQosDscp():
    setUp_qosDscpPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    out = ops1(format('qos dscp -1'))
    assert 'Unknown command' in out
    out = ops1(format('qos dscp 64'))
    assert 'Unknown command' in out

def case_qosDscpPortCommandWithNullQosDscp():
    setUp_qosDscpPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    out = ops1(format('qos dscp'))
    assert 'Command incomplete' in out

def case_qosDscpPortCommandWithInterfaceInLag():
    setUp_qosDscpPort()
    ops1(format('interface {p1}'))
    ops1(format('lag 10'))
    ops1(format('qos trust none'))
    out = ops1(format('qos dscp 1'))
    assert 'cannot' in out

def case_qosDscpPortNoCommand():
    setUp_qosDscpPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust none'))
    ops1(format('qos dscp 1'))
    out = ops1(format('do show interface {p1}'))
    assert 'override' in out
    ops1(format('no qos dscp'))
    out = ops1(format('do show interface {p1}'))
    assert 'override' not in out

def case_qosDscpPortNoCommandWithInterfaceInLag():
    setUp_qosDscpPort()
    ops1(format('interface {p1}'))
    ops1(format('lag 10'))
    ops1(format('qos trust none'))
    out = ops1(format('no qos dscp'))
    assert 'cannot' in out

def case_qosQueueProfileCommand():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('do show qos queue-profile'))
    assert 'p1' in out

def case_qosQueueProfileCommandWithIllegalName():
    setUp_qosQueueProfile()
    out = ops1(format('qos queue-profile '
                         'NameThatIsLongerThan64Characterssssssssssssss'
                         'ssssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('qos queue-profile '
                         'NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosQueueProfileCommandWithNullName():
    setUp_qosQueueProfile()
    out = ops1(format('qos queue-profile'))
    assert 'incomplete' in out

def case_qosQueueProfileCommandWithStrictName():
    setUp_qosQueueProfile()
    out = ops1(format('qos queue-profile strict'))
    assert 'cannot' in out

def case_qosQueueProfileCommandWithAppliedProfile():
    setUp_qosQueueProfile()
    out = ops1(format('qos queue-profile default'))
    assert 'cannot' in out

def case_qosQueueProfileNoCommand():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('do show qos queue-profile'))
    assert 'p1' in out
    ops1(format('no qos queue-profile p1'))
    out = ops1(format('do show qos queue-profile'))
    assert 'p1' not in out

def case_qosQueueProfileNoCommandWithIllegalName():
    setUp_qosQueueProfile()
    out = ops1(format('no qos queue-profile '
                         'NameThatIsLongerThan64Charactersssssssssssssssss'
                         'sssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('no qos queue-profile '
                         'NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosQueueProfileNoCommandWithNullName():
    setUp_qosQueueProfile()
    out = ops1(format('no qos queue-profile'))
    assert 'incomplete' in out

def case_qosQueueProfileNoCommandWithStrictName():
    setUp_qosQueueProfile()
    out = ops1(format('no qos queue-profile strict'))
    assert 'cannot' in out

def case_qosQueueProfileNoCommandWithAppliedProfile():
    setUp_qosQueueProfile()
    out = ops1(format('no qos queue-profile default'))
    assert 'cannot' in out

def case_qosQueueProfileNoCommandWithNonExistentProfile():
    setUp_qosQueueProfile()
    out = ops1(format('no qos queue-profile NonExistent'))
    assert 'does not exist' in out

def case_qosQueueProfileNameCommand():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    ops1(format('name queue 1 QueueName'))
    out = ops1(format('do show qos queue-profile p1'))
    assert 'QueueName' in out

def case_qosQueueProfileNameCommandWithIllegalName():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('name queue 1 '
                         'NameThatIsLongerThan64Characterssssssssssssssss'
                         'ssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('name queue 1 '
                         'NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosQueueProfileNameCommandWithNullName():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('name queue 1'))
    assert 'incomplete' in out

def case_qosQueueProfileNameCommandWithIllegalQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('name queue -1 QueueName'))
    assert 'Unknown command' in out
    out = ops1(format('name queue 8 QueueName'))
    assert 'Unknown command' in out

def case_qosQueueProfileNameCommandWithNullQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('name queue QueueName'))
    assert 'Unknown command' in out

def case_qosQueueProfileNameNoCommand():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    ops1(format('name queue 1 QueueName'))
    out = ops1(format('do show qos queue-profile p1'))
    assert 'QueueName' in out
    ops1(format('no name queue 1'))
    out = ops1(format('do show qos queue-profile p1'))
    assert 'QueueName' not in out

def case_qosQueueProfileNameNoCommandWithIllegalQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('no name queue -1'))
    assert 'Unknown command' in out
    out = ops1(format('no name queue 8'))
    assert 'Unknown command' in out

def case_qosQueueProfileNameNoCommandWithNullQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('no name queue'))
    assert 'incomplete' in out

def case_qosQueueProfileNameNoCommandWithMissingQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('no name queue 2'))
    assert 'does not have queue' in out

def case_qosQueueProfileMapCommand():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    ops1(format('map queue 1 local-priority 2'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '2' in out

def case_qosQueueProfileMapCommandWithIllegalQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('map queue -1 local-priority 2'))
    assert 'Unknown command' in out
    out = ops1(format('map queue 8 local-priority 2'))
    assert 'Unknown command' in out

def case_qosQueueProfileMapCommandWithNullQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('map queue local-priority 2'))
    assert 'Unknown command' in out

def case_qosQueueProfileMapCommandWithIllegalPriority():
    setUp_qosQueueProfile()
    local_priority_range = get_local_priority_range()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('map queue 1 local-priority ' +
                         str(local_priority_range[0] - 1)))
    assert 'Unknown command' in out
    out = ops1(format('map queue 1 local-priority ' +
                         str(local_priority_range[1] + 1)))
    assert 'Unknown command' in out

def case_qosQueueProfileMapCommandWithNullPriority():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('map queue 1 local-priority'))
    assert 'incomplete' in out

def case_qosQueueProfileMapCommandAddsListOfPriorities():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    ops1(format('map queue 1 local-priority 1,2'))
    ops1(format('map queue 1 local-priority 3,4'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '1         1,2,3,4' in out

def case_qosQueueProfileMapNoCommand():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    ops1(format('map queue 1 local-priority 2'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '1         2' in out
    ops1(format('no map queue 1 local-priority 2'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '1         2' not in out

def case_qosQueueProfileMapNoCommandWithIllegalQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('no map queue -1 local-priority 2'))
    assert 'Unknown command' in out
    out = ops1(format('no map queue 8 local-priority 2'))
    assert 'Unknown command' in out

def case_qosQueueProfileMapNoCommandWithNullQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('no map queue local-priority 2'))
    assert 'Unknown command' in out

def case_qosQueueProfileMapNoCommandWithIllegalPriority():
    setUp_qosQueueProfile()
    local_priority_range = get_local_priority_range()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('no map queue 1 local-priority ' +
                         str(local_priority_range[0] - 1)))
    assert 'Unknown command' in out
    out = ops1(format('no map queue 1 local-priority ' +
                         str(local_priority_range[1] + 1)))
    assert 'Unknown command' in out

def case_qosQueueProfileMapNoCommandWithNullPriority():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('no map queue 1 local-priority'))
    assert 'incomplete' in out

def case_qosQueueProfileMapNoCommandDeletesSinglePriority():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    ops1(format('map queue 1 local-priority 2'))
    ops1(format('map queue 1 local-priority 3'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '1         2,3' in out
    ops1(format('no map queue 1 local-priority 2'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '1         2' not in out
    assert '1         3' in out

def case_qosQueueProfileMapNoCommandDeletesAllPriorities():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    ops1(format('map queue 1 local-priority 2'))
    ops1(format('map queue 1 local-priority 3'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '1         2,3' in out
    ops1(format('no map queue 1'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '1         2' not in out
    assert '1         3' not in out

def case_qosQueueProfileMapNoCommandDeletesListOfPriorities():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    ops1(format('map queue 1 local-priority 1,2'))
    ops1(format('map queue 1 local-priority 3,4'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '1         1,2,3,4' in out
    ops1(format('no map queue 1 local-priority 2,3'))
    out = ops1(format('do show qos queue-profile p1'))
    assert '1         1,4' in out

def case_qosQueueProfileMapNoCommandWithMissingQueue():
    setUp_qosQueueProfile()
    ops1(format('qos queue-profile p1'))
    out = ops1(format('no map queue 2'))
    assert 'does not have queue' in out

def case_qosScheduleProfileCommand():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'p1' in out

def case_qosScheduleProfileCommandWithIllegalName():
    setUp_qosScheduleProfile()
    out = ops1(format('qos schedule-profile '
                         'NameThatIsLongerThan64Characterssssssssssssss'
                         'ssssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('qos schedule-profile '
                         'NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosScheduleProfileCommandWithNullName():
    setUp_qosScheduleProfile()
    out = ops1(format('qos schedule-profile'))
    assert 'incomplete' in out

def case_qosScheduleProfileCommandWithStrictName():
    setUp_qosScheduleProfile()
    out = ops1(format('qos schedule-profile strict'))
    assert 'cannot' in out

def case_qosScheduleProfileCommandWithAppliedProfile():
    setUp_qosScheduleProfile()
    out = ops1(format('qos schedule-profile default'))
    assert 'cannot' in out

def case_qosScheduleProfileNoCommand():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'p1' in out
    ops1(format('no qos schedule-profile p1'))
    out = ops1(format('do show qos schedule-profile'))
    assert 'p1' not in out

def case_qosScheduleProfileNoCommandWithIllegalName():
    setUp_qosScheduleProfile()
    out = ops1(format('no qos schedule-profile '
                         'NameThatIsLongerThan64Characterssssssssssssssss'
                         'ssssssssssssssssss'))
    assert 'length up to' in out
    out = ops1(format('no qos schedule-profile '
                         'NameWithIllegalCh@r@cter$'))
    assert 'The allowed characters are' in out

def case_qosScheduleProfileNoCommandWithNullName():
    setUp_qosScheduleProfile()
    out = ops1(format('no qos schedule-profile'))
    assert 'incomplete' in out

def case_qosScheduleProfileNoCommandWithStrictName():
    setUp_qosScheduleProfile()
    out = ops1(format('no qos schedule-profile strict'))
    assert 'cannot' in out

def case_qosScheduleProfileNoCommandWithAppliedProfile():
    setUp_qosScheduleProfile()
    out = ops1(format('no qos schedule-profile default'))
    assert 'cannot' in out

def case_qosScheduleProfileNoCommandWithNonExistentProfile():
    setUp_qosScheduleProfile()
    out = ops1(format('no qos schedule-profile NonExistent'))
    assert 'does not exist' in out

def case_qosScheduleProfileStrictCommand():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    ops1(format('strict queue 1'))
    out = ops1(format('do show qos schedule-profile p1'))
    assert 'strict' in out
    assert '1' in out

def case_qosScheduleProfileStrictCommandWithIllegalQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('strict queue -1'))
    assert 'Unknown command' in out
    out = ops1(format('strict queue 8'))
    assert 'Unknown command' in out

def case_qosScheduleProfileStrictCommandWithNullQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('strict queue'))
    assert 'incomplete' in out

def case_qosScheduleProfileStrictNoCommand():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    ops1(format('strict queue 1'))
    out = ops1(format('do show qos schedule-profile p1'))
    assert 'strict' in out
    ops1(format('no strict queue 1'))
    out = ops1(format('do show qos schedule-profile p1'))
    assert 'strict' not in out

def case_qosScheduleProfileStrictNoCommandWithIllegalQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('no strict queue -1'))
    assert 'Unknown command' in out
    out = ops1(format('no strict queue 8'))
    assert 'Unknown command' in out

def case_qosScheduleProfileStrictNoCommandWithNullQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('no strict queue'))
    assert 'incomplete' in out

def case_qosScheduleProfileStrictNoCommandWithMissingQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('no strict queue 2'))
    assert 'does not have queue' in out

def case_qosScheduleProfileWrrCommand():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    ops1(format('dwrr queue 1 weight 2'))
    out = ops1(format('do show qos schedule-profile p1'))
    assert '1' in out
    assert 'weight' in out
    assert '2' in out

def case_qosScheduleProfileWrrCommandWithIllegalQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('dwrr queue -1 weight 2'))
    assert 'Unknown command' in out
    out = ops1(format('dwrr queue 8 weight 2'))
    assert 'Unknown command' in out

def case_qosScheduleProfileWrrCommandWithNullQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('dwrr queue weight 2'))
    assert 'Unknown command' in out

def case_qosScheduleProfileWrrCommandWithIllegalWeight():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('dwrr queue 1 weight 0'))
    assert 'Unknown command' in out
    out = ops1(format('dwrr queue 1 weight 128'))
    assert 'Unknown command' in out

def case_qosScheduleProfileWrrCommandWithNullWeight():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('dwrr queue 1 weight'))
    assert 'incomplete' in out

def case_qosScheduleProfileWrrNoCommand():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    ops1(format('dwrr queue 1 weight 2'))
    out = ops1(format('do show qos schedule-profile p1'))
    assert '1         dwrr' in out
    ops1(format('no dwrr queue 1'))
    out = ops1(format('do show qos schedule-profile p1'))
    assert '1         dwrr' not in out

def case_qosScheduleProfileWrrNoCommandWithIllegalQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('no dwrr queue -1 weight 2'))
    assert 'Unknown command' in out
    out = ops1(format('no dwrr queue 8 weight 2'))
    assert 'Unknown command' in out

def case_qosScheduleProfileWrrNoCommandWithNullQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('no dwrr queue weight 2'))
    assert 'Unknown command' in out

def case_qosScheduleProfileWrrNoCommandWithIllegalWeight():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('no dwrr queue 1 weight 0'))
    assert 'Unknown command' in out
    out = ops1(format('no dwrr queue 1 weight 128'))
    assert 'Unknown command' in out

def case_qosScheduleProfileWrrNoCommandWithNullWeight():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('no dwrr queue 1 weight'))
    assert 'incomplete' in out

def case_qosScheduleProfileWrrNoCommandWithMissingQueue():
    setUp_qosScheduleProfile()
    ops1(format('qos schedule-profile p1'))
    out = ops1(format('no dwrr queue 2'))
    assert 'does not have queue' in out

def case_qosTrustGlobalCommand():
    setUp_qosTrustGlobal()
    ops1(format('qos trust dscp'))
    ops1(format('qos trust cos'))
    out = ops1(format('do show qos trust'))
    assert 'qos trust cos' in out

def case_qosTrustGlobalCommandWithIllegalQosTrust():
    setUp_qosTrustGlobal()
    out = ops1(format('qos trust illegal'))
    assert 'Unknown command' in out

def case_qosTrustGlobalCommandWithNullQosTrust():
    setUp_qosTrustGlobal()
    out = ops1(format('qos trust'))
    assert 'Command incomplete' in out

def case_qosTrustGlobalNoCommand():
    setUp_qosTrustGlobal()
    ops1(format('qos trust dscp'))
    ops1(format('no qos trust'))
    out = ops1(format('do show qos trust'))
    assert 'qos trust none' in out

def case_qosTrustPortCommand():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust dscp'))
    ops1(format('qos trust cos'))
    out = ops1(format('do show interface {p1}'))
    assert 'qos trust cos' in out

def case_qosTrustPortCommandWithIllegalQosTrust():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    out = ops1(format('qos trust illegal'))
    assert 'Unknown command' in out

def case_qosTrustPortCommandWithNullQosTrust():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    out = ops1(format('qos trust'))
    assert 'Command incomplete' in out

def case_qosTrustPortCommandWithInterfaceInLag():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('lag 10'))
    out = ops1(format('qos trust cos'))
    assert 'QoS Trust cannot be configured on a member of a LAG' in out

def case_qosTrustPortNoCommand():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('qos trust dscp'))
    ops1(format('no qos trust'))
    out = ops1(format('do show interface {p1}'))
    assert 'qos trust none' in out

def case_qosTrustPortNoCommandWithInterfaceInLag():
    setUp_qosTrustPort()
    ops1(format('interface {p1}'))
    ops1(format('lag 10'))
    out = ops1(format('no qos trust'))
    assert 'QoS Trust cannot be configured on a member of a LAG' in out

def test_qos_ct_cli(topology, setup):
    case_qosApplyGlobalCommand()
    case_qosApplyGlobalCommandWithDuplicateQueueProfileQueue()
    case_qosApplyGlobalCommandWithMissingQueueProfileQueue()
    case_qosApplyGlobalCommandWithMissingScheduleProfileQueue()
    case_qosApplyGlobalCommandWithIllegalQueueProfile()
    case_qosApplyGlobalCommandWithNullQueueProfile()
    case_qosApplyGlobalCommandWithMissingQueueProfile()
    case_qosApplyGlobalCommandWithIllegalScheduleProfile()
    case_qosApplyGlobalCommandWithNullScheduleProfile()
    case_qosApplyGlobalCommandWithMissingScheduleProfile()
    case_qosApplyGlobalCommandWithStrictScheduleProfile()
    case_qosApplyGlobalCommandWithAllStrict()
    case_qosApplyGlobalCommandWithAllWrr()
    case_qosApplyGlobalCommandWithAllWrrWithMaxStrict()
    case_qosApplyGlobalCommandWithHigherStrictLowerWrr()
    case_qosApplyGlobalCommandWithLowerStrictHigherWrr()
    case_qosApplyGlobalCommandAndThenRestoreDefaultQueueProfile()
    case_qosApplyGlobalCommandAndThenRestoreDefaultScheduleProfile()
    case_qosApplyGlobalCommandWithPortScheduleProfileWithDifferentQueues()
    case_qosApplyGlobalCommandWithPortScheduleProfileStrict()

    case_qosApplyPortCommand()
    case_qosApplyPortCommandWithMissingScheduleProfileQueue()
    case_qosApplyPortCommandWithIllegalScheduleProfile()
    case_qosApplyPortCommandWithNullScheduleProfile()
    case_qosApplyPortCommandWithInterfaceInLag()
    case_qosApplyPortCommandWithMissingScheduleProfile()
    case_qosApplyPortCommandWithStrictScheduleProfile()
    case_qosApplyPortCommandWithAllStrict()
    case_qosApplyPortCommandWithAllWrr()
    case_qosApplyPortCommandWithAllWrrWithMaxStrict()
    case_qosApplyPortCommandWithHigherStrictLowerWrr()
    case_qosApplyPortCommandWithLowerStrictHigherWrr()
    case_qosApplyPortNoCommand()
    case_qosApplyPortNoCommandWithInterfaceInLag()

    case_qosCosMapCommand()
    case_qosCosMapCommandWithIllegalCodePoint()
    case_qosCosMapCommandWithNullCodePoint()
    case_qosCosMapCommandWithIllegalLocalPriority()
    case_qosCosMapCommandWithNullLocalPriority()
    case_qosCosMapCommandWithIllegalColor()
    case_qosCosMapCommandWithNullColor()
    case_qosCosMapCommandWithIllegalName()
    case_qosCosMapCommandWithNullName()
    case_qosCosMapNoCommand()

    case_qosCosPortCommand()
    case_qosCosPortCommandWithSystemTrustNoneAndPortTrustCos()
    case_qosCosPortCommandWithSystemTrustNoneAndPortTrustMissing()
    case_qosCosPortCommandWithSystemTrustCosAndPortTrustNone()
    case_qosCosPortCommandWithSystemTrustCosAndPortTrustMissing()
    case_qosCosPortCommandWithIllegalQosCos()
    case_qosCosPortCommandWithNullQosCos()
    case_qosCosPortCommandWithInterfaceInLag()
    case_qosCosPortNoCommand()
    case_qosCosPortNoCommandWithInterfaceInLag()

    case_qosDscpMapCommand()
    case_qosDscpMapCommandWithIllegalCodePoint()
    case_qosDscpMapCommandWithNullCodePoint()
    case_qosDscpMapCommandWithIllegalLocalPriority()
    case_qosDscpMapCommandWithNullLocalPriority()
    case_qosDscpMapCommandWithIllegalCos()
    case_qosDscpMapCommandWithNullCos()
    case_qosDscpMapCommandWithIllegalColor()
    case_qosDscpMapCommandWithNullColor()
    case_qosDscpMapCommandWithIllegalName()
    case_qosDscpMapCommandWithNullName()
    case_qosDscpMapNoCommand()

    case_qosDscpPortCommand()
    case_qosDscpPortCommandWithSystemTrustNoneAndPortTrustDscp()
    case_qosDscpPortCommandWithSystemTrustNoneAndPortTrustMissing()
    case_qosDscpPortCommandWithSystemTrustDscpAndPortTrustNone()
    case_qosDscpPortCommandWithSystemTrustDscpAndPortTrustMissing()
    case_qosDscpPortCommandWithIllegalQosDscp()
    case_qosDscpPortCommandWithNullQosDscp()
    case_qosDscpPortCommandWithInterfaceInLag()
    case_qosDscpPortNoCommand()
    case_qosDscpPortNoCommandWithInterfaceInLag()

    case_qosQueueProfileCommand()
    case_qosQueueProfileCommandWithIllegalName()
    case_qosQueueProfileCommandWithNullName()
    case_qosQueueProfileCommandWithStrictName()
    case_qosQueueProfileCommandWithAppliedProfile()
    case_qosQueueProfileNoCommand()
    case_qosQueueProfileNoCommandWithIllegalName()
    case_qosQueueProfileNoCommandWithNullName()
    case_qosQueueProfileNoCommandWithStrictName()
    case_qosQueueProfileNoCommandWithAppliedProfile()
    case_qosQueueProfileNoCommandWithNonExistentProfile()
    case_qosQueueProfileNameCommand()
    case_qosQueueProfileNameCommandWithIllegalName()
    case_qosQueueProfileNameCommandWithNullName()
    case_qosQueueProfileNameCommandWithIllegalQueue()
    case_qosQueueProfileNameCommandWithNullQueue()
    case_qosQueueProfileNameNoCommand()
    case_qosQueueProfileNameNoCommandWithIllegalQueue()
    case_qosQueueProfileNameNoCommandWithNullQueue()
    case_qosQueueProfileNameNoCommandWithMissingQueue()
    case_qosQueueProfileMapCommand()
    case_qosQueueProfileMapCommandWithIllegalQueue()
    case_qosQueueProfileMapCommandWithNullQueue()
    case_qosQueueProfileMapCommandWithIllegalPriority()
    case_qosQueueProfileMapCommandWithNullPriority()
    case_qosQueueProfileMapCommandAddsListOfPriorities()
    case_qosQueueProfileMapNoCommand()
    case_qosQueueProfileMapNoCommandWithIllegalQueue()
    case_qosQueueProfileMapNoCommandWithNullQueue()
    case_qosQueueProfileMapNoCommandWithIllegalPriority()
    case_qosQueueProfileMapNoCommandWithNullPriority()
    case_qosQueueProfileMapNoCommandDeletesSinglePriority()
    case_qosQueueProfileMapNoCommandDeletesAllPriorities()
    case_qosQueueProfileMapNoCommandDeletesListOfPriorities()
    case_qosQueueProfileMapNoCommandWithMissingQueue()

    case_qosScheduleProfileCommand()
    case_qosScheduleProfileCommandWithIllegalName()
    case_qosScheduleProfileCommandWithNullName()
    case_qosScheduleProfileCommandWithStrictName()
    case_qosScheduleProfileCommandWithAppliedProfile()
    case_qosScheduleProfileNoCommand()
    case_qosScheduleProfileNoCommandWithIllegalName()
    case_qosScheduleProfileNoCommandWithNullName()
    case_qosScheduleProfileNoCommandWithStrictName()
    case_qosScheduleProfileNoCommandWithAppliedProfile()
    case_qosScheduleProfileNoCommandWithNonExistentProfile()
    case_qosScheduleProfileStrictCommand()
    case_qosScheduleProfileStrictCommandWithIllegalQueue()
    case_qosScheduleProfileStrictCommandWithNullQueue()
    case_qosScheduleProfileStrictNoCommand()
    case_qosScheduleProfileStrictNoCommandWithIllegalQueue()
    case_qosScheduleProfileStrictNoCommandWithNullQueue()
    case_qosScheduleProfileStrictNoCommandWithMissingQueue()
    case_qosScheduleProfileWrrCommand()
    case_qosScheduleProfileWrrCommandWithIllegalQueue()
    case_qosScheduleProfileWrrCommandWithNullQueue()
    case_qosScheduleProfileWrrCommandWithIllegalWeight()
    case_qosScheduleProfileWrrCommandWithNullWeight()
    case_qosScheduleProfileWrrNoCommand()
    case_qosScheduleProfileWrrNoCommandWithIllegalQueue()
    case_qosScheduleProfileWrrNoCommandWithNullQueue()
    case_qosScheduleProfileWrrNoCommandWithIllegalWeight()
    case_qosScheduleProfileWrrNoCommandWithNullWeight()
    case_qosScheduleProfileWrrNoCommandWithMissingQueue()

    case_qosTrustGlobalCommand()
    case_qosTrustGlobalCommandWithIllegalQosTrust()
    case_qosTrustGlobalCommandWithNullQosTrust()
    case_qosTrustGlobalNoCommand()

    case_qosTrustPortCommand()
    case_qosTrustPortCommandWithIllegalQosTrust()
    case_qosTrustPortCommandWithNullQosTrust()
    case_qosTrustPortCommandWithInterfaceInLag()
    case_qosTrustPortNoCommand()
    case_qosTrustPortNoCommandWithInterfaceInLag()
