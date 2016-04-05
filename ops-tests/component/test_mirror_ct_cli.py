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
import time

TOPOLOGY = """
# +-------+
# |  ops1 |
# +-------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
"""

dut01 = None
switch_ip = None

@pytest.fixture(scope="module")
def setup(topology):
    global dut01
    dut01 = topology.get("ops1")
    assert dut01 is not None

    global switch_ip
    switch_ip = get_switch_ip(dut01)
    assert switch_ip is not None

    dut01('end')
    dut01('configure terminal')
    dut01('interface 1')
    dut01('interface 2')
    dut01('interface 3')
    dut01('interface 4')
    dut01('end')

def get_switch_ip(switch):
    switch_ip = switch('python -c \"import socket; '
                       'print socket.gethostbyname(socket.gethostname())\"',
                       shell='bash')
    switch_ip = switch_ip.rstrip('\r\n')
    return switch_ip

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

def case_1_activate_ms_foo_succeeds():
    dut01('configure terminal')
    dut01('mirror session foo')
    dut01('source interface 2 both')
    dut01('destination interface 3')
    dut01('no shutdown')
    dut01('end')

    out = dut01('show mirror')
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert contains_line_with(out, ["foo", "active"])

    out = dut01('show mirror foo')
    assert 'Mirror Session: foo' in out
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert 'Status: active' in out
    assert 'Source: interface 2 both' in out
    assert 'Destination: interface 3' in out

def case_2_add_second_source_to_active_mirror_session_foo_succeeds():
    dut01('configure terminal')
    dut01('mirror session foo')
    dut01('source interface 1 rx')
    dut01('end')

    out = dut01('show mirror foo')
    assert 'Mirror Session: foo' in out
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert 'Status: active' in out
    assert 'Source: interface 1 rx' in out
    assert 'Source: interface 2 both' in out
    assert 'Destination: interface 3' in out

def case_3_remove_first_source_to_active_mirror_session_foo_succeeds():
    dut01('configure terminal')
    dut01('mirror session foo')
    dut01('no source interface 2 tx')
    dut01('end')

    out = dut01('show mirror foo')
    assert 'Mirror Session: foo' in out
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert 'Status: active' in out
    assert 'Source: interface 1 rx' in out
    assert 'Destination: interface 3' in out

def case_4_activate_mirror_session_bar_succeeds():
    dut01('configure terminal')
    dut01('mirror session bar')
    dut01('source interface 2 tx')
    dut01('destination interface 4')
    dut01('no shutdown')
    dut01('end')

    out = dut01('show mirror')
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert contains_line_with(out, ["bar", "active"])

    out = dut01('show mirror bar')
    assert 'Mirror Session: bar' in out
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert 'Status: active' in out
    assert 'Source: interface 2 tx' in out
    assert 'Destination: interface 4' in out

    out = dut01('show running-config')
    assert 'mirror session foo' in out
    assert 'mirror session bar' in out

def case_5_attempt_another_session_using_existing_destination_fails():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('source interface 1 rx')
    dut01('destination interface 4')
    out = dut01('no shutdown')
    assert 'Interface (4) already in use as ' + \
        'destination in active session bar' in out
    dut01('end')

    out = dut01('show mirror')
    assert contains_line_with(out, ["dup", "shutdown"])

    out = dut01('show mirror dup')
    assert 'Mirror Session: dup' in out
    assert 'Status: new' in out
    assert 'Source: interface 1 rx' in out
    assert 'Destination: interface 4' in out

    dut01('configure terminal')
    dut01('no mirror session dup')
    dut01('end')

def case_6_attempt_another_session_with_destination_using_existing_rx_source_interface_fails():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('source interface 2 rx')
    dut01('destination interface 1')
    out = dut01('no shutdown')
    assert 'Interface (1) already in use as ' + \
        'source in active session' in out
    dut01('end')

    dut01('configure terminal')
    dut01('no mirror session dup')
    dut01('end')

def case_7_attempt_another_session_with_destination_using_existing_tx_source_interface_fails():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('source interface 1 rx')
    dut01('destination interface 2')
    out = dut01('no shutdown')
    assert 'Interface (2) already in use as ' + \
        'source in active session' in out
    dut01('end')

    dut01('configure terminal')
    dut01('no mirror session dup')
    dut01('end')

def case_8_attempt_another_session_with_source_rx_using_existing_destination_interface_fails():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('source interface 3 rx')
    dut01('destination interface 4')
    out = dut01('no shutdown')
    assert 'Interface (4) already in use as ' + \
        'destination in active session' in out
    dut01('end')

    dut01('configure terminal')
    dut01('no mirror session dup')
    dut01('end')

def case_9_attempt_another_session_with_source_tx_using_existing_destination_interface_fails():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('source interface 3 tx')
    dut01('destination interface 4')
    out = dut01('no shutdown')
    assert 'Interface (4) already in use as ' + \
        'destination in active session' in out
    dut01('end')

    dut01('configure terminal')
    dut01('no mirror session dup')
    dut01('end')

def case_10_attempt_another_session_with_same_source_rx_and_destination_interface_fails():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('source interface 3 rx')
    out = dut01('destination interface 3')
    assert 'Cannot add destination, interface 3 is already a source' in out
    dut01('end')

    dut01('configure terminal')
    dut01('no mirror session dup')
    dut01('end')

def case_11_attempt_another_session_with_same_source_tx_and_destination_interface_fails():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('source interface 3 tx')
    out = dut01('destination interface 3')
    assert 'Cannot add destination, interface 3 is already a source' in out
    dut01('end')

    dut01('configure terminal')
    dut01('no mirror session dup')
    dut01('end')

def case_12_attempt_another_session_without_a_destination_interface_fails():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('source interface 1 tx')
    out = dut01('no shutdown')
    assert 'No mirror destination interface configured' in out
    dut01('end')

    dut01('configure terminal')
    dut01('no mirror session dup')
    dut01('end')

def case_13_create_inactive_duplicate_mirror_session_dup_succeeds():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('source interface 1 rx')
    dut01('destination interface 3')
    dut01('end')

    out = dut01('show mirror')
    assert contains_line_with(out, ["dup", "shutdown"])

def case_14_deactivate_mirror_session_foo():
    dut01('configure terminal')
    dut01('mirror session foo')
    dut01('shutdown')
    dut01('end')

    out = dut01('show mirror')
    assert contains_line_with(out, ["foo", "shutdown"])

def case_15_activate_mirror_session_dup():
    dut01('configure terminal')
    dut01('mirror session dup')
    dut01('no shutdown')
    dut01('end')

    out = dut01('show mirror')
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert contains_line_with(out, ["dup", "active"])

def case_16_remove_inactive_mirror_session_foo_succeeds():
    dut01('configure terminal')
    dut01('no mirror session foo')
    dut01('no shutdown')
    dut01('end')

    out = dut01('show mirror')
    assert 'foo' not in out

    out = dut01('show mirror foo')
    assert 'Invalid mirror session' in out

def case_17_remove_active_mirror_session_dup_succeeds():
    dut01('configure terminal')
    dut01('no mirror session dup')
    dut01('end')

    out = dut01('show mirror')
    assert 'dup' not in out

    out = dut01('show mirror dup')
    assert 'Invalid mirror session' in out

def case_18_remove_active_mirror_session_bar_succeeds():
    dut01('configure terminal')
    dut01('no mirror session bar')
    dut01('end')

    out = dut01('show mirror bar')
    assert 'Invalid mirror session' in out

    out = dut01('show mirror')
    assert out == ''

    out = dut01('show running-config')
    assert 'mirror session' not in out

def case_19_create_lag_succeeds():
    dut01('configure terminal')
    dut01('interface lag 100')
    dut01('no shutdown')
    dut01('interface 1')
    dut01('lag 100')
    dut01('interface 2')
    dut01('lag 100')
    dut01('end')

def case_20_mirror_session_with_source_lag_succeeds():
    dut01('configure terminal')
    dut01('mirror session foo')
    dut01('source interface lag100 rx')
    dut01('destination interface 3')
    dut01('no shutdown')
    dut01('end')

    out = dut01('show mirror')
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert contains_line_with(out, ["foo", "active"])

    out = dut01('show mirror foo')
    assert 'Mirror Session: foo' in out
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert 'Status: active' in out
    assert 'Source: interface lag100 rx' in out
    assert 'Destination: interface 3' in out

    dut01('configure terminal')
    dut01('no mirror session foo')
    dut01('end')

def case_21_mirror_session_with_destination_lag_succeeds():
    dut01('configure terminal')
    dut01('mirror session bar')
    dut01('source interface 3 rx')
    dut01('destination interface lag100')
    dut01('no shutdown')
    dut01('end')

    out = dut01('show mirror')
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert contains_line_with(out, ["bar", "active"])

    out = dut01('show mirror bar')
    assert 'Mirror Session: bar' in out
    # TODO: once mirrors are able to be activated in the container, enable this
#     assert 'Status: active' in out
    assert 'Source: interface 3 rx' in out
    assert 'Destination: interface lag100' in out

    dut01('configure terminal')
    dut01('no mirror session bar')
    dut01('end')

def test_ct_mirror_rest_custom_validators(topology, setup):
    case_1_activate_ms_foo_succeeds()
    case_2_add_second_source_to_active_mirror_session_foo_succeeds()
    case_3_remove_first_source_to_active_mirror_session_foo_succeeds()
    case_4_activate_mirror_session_bar_succeeds()
    case_5_attempt_another_session_using_existing_destination_fails()
    case_6_attempt_another_session_with_destination_using_existing_rx_source_interface_fails()
    case_7_attempt_another_session_with_destination_using_existing_tx_source_interface_fails()
    case_8_attempt_another_session_with_source_rx_using_existing_destination_interface_fails()
    case_9_attempt_another_session_with_source_tx_using_existing_destination_interface_fails()
    case_10_attempt_another_session_with_same_source_rx_and_destination_interface_fails()
    case_11_attempt_another_session_with_same_source_tx_and_destination_interface_fails()
    case_12_attempt_another_session_without_a_destination_interface_fails()
    case_13_create_inactive_duplicate_mirror_session_dup_succeeds()
    case_14_deactivate_mirror_session_foo()
    case_15_activate_mirror_session_dup()
    case_16_remove_inactive_mirror_session_foo_succeeds()
    case_17_remove_active_mirror_session_dup_succeeds()
    case_18_remove_active_mirror_session_bar_succeeds()
    case_19_create_lag_succeeds()
    case_20_mirror_session_with_source_lag_succeeds()
    case_21_mirror_session_with_destination_lag_succeeds()
