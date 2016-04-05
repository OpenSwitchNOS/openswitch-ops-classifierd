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

import json
import http.client

TOPOLOGY = """
# +-------+
# |  ops1 |
# +-------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
"""

dut01 = None
switch_ip = None

def get_mirror_url(name=""):
    return "/rest/v1/system/bridges/bridge_normal/mirrors/" + name

def get_port_url(port):
    return "/rest/v1/system/ports/" + str(port)

def create_existing_mirror_data():
    existing_mirror_data = {
        "configuration": {
            "name": "existing_mirror",
            "active": True,
            "select_src_port": [get_port_url(10)],
            "select_dst_port": [get_port_url(11)],
            "output_port": get_port_url(12)
        }
    }
    return deepcopy(existing_mirror_data)

def create_new_mirror_data():
    new_mirror_data = {
        "configuration": {
            "name": "new_mirror",
            "active": True,
            "select_src_port": [get_port_url(20)],
            "select_dst_port": [get_port_url(21)],
            "output_port": get_port_url(22)
        }
    }
    return deepcopy(new_mirror_data)

@pytest.fixture(scope="module")
def setup(topology):
    global dut01
    dut01 = topology.get("ops1")
    assert dut01 is not None

    global switch_ip
    switch_ip = get_switch_ip(dut01)
    assert switch_ip is not None

    rest_sanity_check(switch_ip)

    dut01('end')
    dut01('configure terminal')
    dut01('interface 1')
    dut01('interface 2')
    dut01('interface 3')
    dut01('interface 4')
    dut01('interface lag 10')

def get_switch_ip(switch):
    switch_ip = switch('python -c \"import socket; '
                       'print socket.gethostbyname(socket.gethostname())\"',
                       shell='bash')
    switch_ip = switch_ip.rstrip('\r\n')
    return switch_ip

def rest_sanity_check(switch_ip):
    # Check if bridge_normal is ready, loop until ready or timeout finish
    system_path = "/rest/v1/system"
    bridge_path = "/rest/v1/system/bridges/bridge_normal"
    count = 1
    max_retries = 60  # 1 minute
    while count <= max_retries:
        try:
            status_system, response_system = \
                execute_request(system_path, "GET", None, switch_ip)
            status_bridge, response_bridge = \
                execute_request(bridge_path, "GET", None, switch_ip)

            if status_system is http.client.OK and \
                    status_bridge is http.client.OK:
                break
        except:
            pass

        count += 1
        time.sleep(1)

    assert count <= max_retries, "Switch Sanity check failure: After waiting \
        %d seconds, the switch is still not ready to run the tests" \
        % max_retries

def execute_request(url, method, data, rest_server_ip):
    command = '2>&1'

    curl_command = ('curl -v -k -H \"Content-Type: application/json\" '
                    '--retry 3 ')
    curl_xmethod = '-X ' + method + ' '
    curl_url = '\"https://' + rest_server_ip + url + '\" '
    curl_command += curl_xmethod

    if (data):
        curl_command += '-d \'' + data + '\' '

    curl_command += curl_url

    if (command):
        curl_command += command

    result = dut01(curl_command, shell='bash')

    status_code = get_status_code(result)
    response_data = get_response_data(result)

    return status_code, response_data

def get_status_code(request_output):
    for line in request_output.split('\n'):
        if '< HTTP/1.1' in line:
            status_code = int(line.split(' ')[2])
            return status_code

def get_response_data(request_output):
    for line in request_output.split('\n'):
        if line.startswith('{'):
            return line
    return ''

def rest_post_succeeds(mirror_data):
    response_status, response_data = execute_request(
        get_mirror_url(), "POST",
        json.dumps(mirror_data), switch_ip)
    assert response_status == http.client.CREATED
    assert response_data is ''

def rest_post_fails(mirror_data, error_message):
    response_status, response_data = execute_request(
        get_mirror_url(), "POST",
        json.dumps(mirror_data), switch_ip)
    assert response_status == http.client.BAD_REQUEST
    assert error_message in response_data

def rest_patch(mirror_name, mirror_data):
    response_status, response_data = execute_request(
        get_mirror_url(mirror_name), "PATCH",
        json.dumps(mirror_data), switch_ip)
    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def rest_put_succeeds(mirror_name, mirror_data):
    response_status, response_data = execute_request(
        get_mirror_url(mirror_name), "PUT",
        json.dumps(mirror_data), switch_ip)
    assert response_status == http.client.OK
    assert response_data is ''

def rest_put_fails(mirror_name, mirror_data, error_message):
    response_status, response_data = execute_request(
        get_mirror_url(mirror_name), "PUT",
        json.dumps(mirror_data), switch_ip)
    assert response_status == http.client.BAD_REQUEST
    assert error_message in response_data

def rest_delete(mirror_name):
    response_status, response_data = execute_request(
        get_mirror_url(mirror_name),
        "DELETE", None, switch_ip)
    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def rest_get_succeeds(mirror_name):
    response_status, response_data = execute_request(
        get_mirror_url(mirror_name), "GET",
        None, switch_ip)

    assert response_status == http.client.OK

    return response_data

def rest_get_fails(mirror_name):
    response_status, response_data = execute_request(
        get_mirror_url(mirror_name), "GET",
        None, switch_ip)

    assert response_status == http.client.NOT_FOUND

def case_1_activate_ms_foo_succeeds():
    mirror_name = "foo"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url(2)],
            "select_dst_port": [get_port_url(2)],
            "output_port": get_port_url(3),
            "active": True
        }
    }

    rest_post_succeeds(mirror_data)

    actual_data = rest_get_succeeds(mirror_name)
    assert "\"name\": \"foo\"" in actual_data
    assert "\"select_src_port\": [\"" + get_port_url(2) + "\"]," \
        in actual_data
    assert "\"select_dst_port\": [\"" + get_port_url(2) + "\"]" \
        in actual_data
    assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
    assert "\"active\": true" in actual_data

def case_2_add_second_source_to_active_ms_foo_succeeds():
    mirror_name = "foo"
    mirror_data = [{"op": "add", "path": "/select_src_port/0",
                              "value": get_port_url(1)}]

    rest_patch(mirror_name, mirror_data)

    actual_data = rest_get_succeeds(mirror_name)
    assert "\"name\": \"foo\"" in actual_data
    assert "\"select_src_port\": [\"" + get_port_url(1) + "\","
    " \" + get_port_url(2\"]," in actual_data
    assert "\"select_dst_port\": [\"" + get_port_url(2) + "\"]" \
        in actual_data
    assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
    assert "\"active\": true" in actual_data

def case_3_remove_first_source_from_active_ms_foo_succeeds():
    mirror_name = "foo"
    mirror_data = {
        "configuration": {
            "select_src_port": [get_port_url(1)],
            "select_dst_port": []
        }
    }

    # TODO: use patch instead of put.
    rest_put_succeeds(mirror_name, mirror_data)

    actual_data = rest_get_succeeds(mirror_name)
    assert "\"name\": \"foo\"" in actual_data
    assert "\"select_src_port\": [\"" + get_port_url(1) + "\"]," \
        in actual_data
    assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
    assert "\"active\": true" in actual_data

def case_4_attempt_another_ms_without_an_output_port_fails():
    mirror_name = "bar"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url(2)],
            "active": True
        }
    }

    rest_post_fails(mirror_data, "output port cannot be empty.")

    rest_get_fails(mirror_name)

def case_5_attempt_another_ms_without_any_source_ports_fails():
    mirror_name = "bar"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "output_port": get_port_url(4),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "select src port and select dst port cannot both be empty")

    rest_get_fails(mirror_name)

def case_6_activate_ms_bar_succeeds():
    mirror_name = "bar"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_dst_port": [get_port_url(1)],
            "output_port": get_port_url(4),
            "active": True
        }
    }

    rest_post_succeeds(mirror_data)

    actual_data = rest_get_succeeds(mirror_name)
    assert "\"name\": \"bar\"" in actual_data
    assert "\"select_dst_port\": [\"" + get_port_url(1) + "\"]" \
        in actual_data
    assert "output_port\": [\"" + get_port_url(4) + "\"]" in actual_data
    assert "\"active\": true" in actual_data

def case_7_replace_source_1_with_2_in_active_ms_bar_succeeds():
    mirror_name = "bar"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_dst_port": [get_port_url(2)],
            "output_port": get_port_url(4),
            "active": True
        }
    }

    rest_put_succeeds(mirror_name, mirror_data)

    actual_data = rest_get_succeeds(mirror_name)
    assert "\"name\": \"bar\"" in actual_data
    assert "\"select_dst_port\": [\"" + get_port_url(2) + "\"]" \
        in actual_data
    assert "output_port\": [\"" + get_port_url(4) + "\"]" in actual_data
    assert "\"active\": true" in actual_data

def case_8_attempt_another_ms_using_existing_destination_fails():
    mirror_name = "dup"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url(1)],
            "output_port": get_port_url(3),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "output port cannot be an output port of another active mirror")

    rest_get_fails(mirror_name)

def case_9_attempt_another_ms_op_u_e_rx_source_interface_fails():
    mirror_name = "dup"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url(2)],
            "output_port": get_port_url(1),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "output port cannot be a select src port of another active mirror")

    rest_get_fails(mirror_name)

def case_10_attempt_another_ms_op_u_e_tx_source_interface_fails():
    mirror_name = "dup"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url(1)],
            "output_port": get_port_url(2),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "output port cannot be a select dst port of another active mirror")

    rest_get_fails(mirror_name)

def case_11_attempt_another_ms_rx_source_u_e_op_fails():
    mirror_name = "dup"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url(3)],
            "output_port": get_port_url(4),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "cannot be")

    rest_get_fails(mirror_name)

def case_12_attempt_another_ms_tx_source_u_e_op_fails():
    mirror_name = "dup"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_dst_port": [get_port_url(3)],
            "output_port": get_port_url(4),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "cannot be")

    rest_get_fails(mirror_name)

def case_13_attempt_another_ms_with_same_rx_source_and_op_fails():
    mirror_name = "dup"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url(4)],
            "output_port": get_port_url(4),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "output port cannot also be a select src port")

    rest_get_fails(mirror_name)

def case_14_attempt_another_ms_with_same_tx_source_and_op_fails():
    mirror_name = "dup"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_dst_port": [get_port_url(4)],
            "output_port": get_port_url(4),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "output port cannot also be a select dst port")

    rest_get_fails(mirror_name)

def case_15_create_inactive_duplicate_of_mirror_session_succeeds():
    mirror_name = "dup"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url(1)],
            "output_port": get_port_url(3)
        }
    }

    rest_post_succeeds(mirror_data)

    actual_data = rest_get_succeeds(mirror_name)
    assert "\"name\": \"dup\"" in actual_data
    assert "\"select_src_port\": [\"" + get_port_url(1) + "\"]," \
        in actual_data
    assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data

def case_16_deactivate_mirror_session_foo_succeeds():
    mirror_name = "foo"
    mirror_data = {
        "configuration": {
            "active": False
        }
    }

    # TODO: use patch instead of put.
    rest_put_succeeds(mirror_name, mirror_data)

    actual_data = rest_get_succeeds(mirror_name)
    assert "\"name\": \"foo\"" in actual_data
    assert "\"select_src_port\": [\"" + get_port_url(1) + "\"]," \
        in actual_data
    assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
    assert "\"active\": false" in actual_data

def case_17_activate_mirror_session_dup_succeeds():
    mirror_name = "dup"
    mirror_data = {
        "configuration": {
            "active": True
        }
    }

    # TODO: use patch instead of put.
    rest_put_succeeds(mirror_name, mirror_data)

    actual_data = rest_get_succeeds(mirror_name)
    assert "\"name\": \"dup\"" in actual_data
    assert "\"select_src_port\": [\"" + get_port_url(1) + "\"]," \
        in actual_data
    assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
    assert "\"active\": true" in actual_data

def case_18_remove_inactivate_mirror_session_foo_succeeds():
    mirror_name = "foo"

    rest_delete(mirror_name)

    rest_get_fails(mirror_name)

def case_19_remove_activate_mirror_session_dup_succeeds():
    mirror_name = "dup"

    rest_delete(mirror_name)

    rest_get_fails(mirror_name)

def case_20_remove_activate_mirror_session_bar_succeeds():
    mirror_name = "bar"

    rest_delete(mirror_name)

    rest_get_fails(mirror_name)

def case_add_active_mirror_foo_non_system_interface_fails():
    mirror_name = "foo"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url("bridge_normal")],
            "select_dst_port": [get_port_url(2)],
            "output_port": get_port_url(3),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "mirror can only contain interfaces of type system")

    rest_get_fails(mirror_name)

def case_add_active_mirror_foo_empty_lag_fails():
    mirror_name = "foo"
    mirror_data = {
        "configuration": {
            "name": mirror_name,
            "select_src_port": [get_port_url("lag10")],
            "select_dst_port": [get_port_url(2)],
            "output_port": get_port_url(3),
            "active": True
        }
    }

    rest_post_fails(mirror_data, \
        "must contain at least one interface")

    rest_get_fails(mirror_name)

def test_ct_mirror_rest_custom_validators(topology, setup):
    case_1_activate_ms_foo_succeeds()
    case_2_add_second_source_to_active_ms_foo_succeeds()
    case_3_remove_first_source_from_active_ms_foo_succeeds()
    case_4_attempt_another_ms_without_an_output_port_fails()
    case_5_attempt_another_ms_without_any_source_ports_fails()
    case_6_activate_ms_bar_succeeds()
    case_7_replace_source_1_with_2_in_active_ms_bar_succeeds()
    case_8_attempt_another_ms_using_existing_destination_fails()
    case_9_attempt_another_ms_op_u_e_rx_source_interface_fails()
    case_10_attempt_another_ms_op_u_e_tx_source_interface_fails()
    case_11_attempt_another_ms_rx_source_u_e_op_fails()
    case_12_attempt_another_ms_tx_source_u_e_op_fails()
    case_13_attempt_another_ms_with_same_rx_source_and_op_fails()
    case_14_attempt_another_ms_with_same_tx_source_and_op_fails()
    case_15_create_inactive_duplicate_of_mirror_session_succeeds()
    case_16_deactivate_mirror_session_foo_succeeds()
    case_17_activate_mirror_session_dup_succeeds()
    case_18_remove_inactivate_mirror_session_foo_succeeds()
    case_19_remove_activate_mirror_session_dup_succeeds()
    case_20_remove_activate_mirror_session_bar_succeeds()
    case_add_active_mirror_foo_non_system_interface_fails()
    case_add_active_mirror_foo_empty_lag_fails()
