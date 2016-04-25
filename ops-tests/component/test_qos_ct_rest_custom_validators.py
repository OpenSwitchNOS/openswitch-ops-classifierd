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

def rest_sanity_check(switch_ip):
    # Check if bridge_normal is ready, loop until ready or timeout finish
    system_path = "/rest/v1/system"
    bridge_path = "/rest/v1/system/bridges/bridge_normal"
    count = 1
    max_retries = 60  # 1 minute
    while count <= max_retries:
        try:
            login_url = "https://" + str(switch_ip) + "/login"
            ops1("curl -D /tmp/header$$ --noproxy " + str(switch_ip) + \
                 " -X POST --fail -ksSfL --url \"" + login_url + \
                 "\" -H \"Content-Type: " + \
                 "application/x-www-form-urlencoded\" " + \
                 "-d \"username=netop&password=netop\"", shell='bash')

            ops1("grep Set-Cookie /tmp/header$$|awk '{print $2}' " + \
                          "> /tmp/COOKIE", shell='bash')

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
    count = 1
    max_retries = 60  # 1 minute
    while count <= max_retries:
        try:
            login_url = "https://" + str(switch_ip) + "/login"
            ops1("curl -D /tmp/header$$ --noproxy " + str(switch_ip) + \
                 " -X POST --fail -ksSfL --url \"" + login_url + \
                 "\" -H \"Content-Type: " + \
                 "application/x-www-form-urlencoded\" " + \
                 "-d \"username=netop&password=netop\"", shell='bash')

            ops1("grep Set-Cookie /tmp/header$$|awk '{print $2}' " + \
                          "> /tmp/COOKIE", shell='bash')

            command = '2>&1'

            curl_command = ('curl -v -k -H \"Content-Type: application/json\" '
                            '-H \"Cookie: $(cat /tmp/COOKIE)\" '
                            '--retry 3 ')
            curl_xmethod = '-X ' + method + ' '
            curl_url = '\"https://' + rest_server_ip + url + '\" '
            curl_command += curl_xmethod

            if (data):
                curl_command += '-d \'' + data + '\' '

            curl_command += curl_url

            if (command):
                curl_command += command

            result = ops1(curl_command, shell='bash')

            status_code = get_status_code(result)
            response_data = get_response_data(result)

            if "Unauthorized" not in response_data:
                # Authentication succeeded. Return the response.
                return status_code, response_data
        except:
            pass

        count += 1
        time.sleep(1)

    assert count <= max_retries, "Unable to send curl command."

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

def get_port_url(port):
    s = "/rest/v1/system/ports/" + port
    return format(s)

port_data = {
    "configuration": {
        "qos": "/rest/v1/system/qoss/p1",
        "qos_config": {
            "qos_trust": "none",
            "dscp_override": "1"
        }
    }
}

q_profile_entry_post_url = "/rest/v1/system/q_profiles/p1/q_profile_entries"
q_profile_entry_url = q_profile_entry_post_url + "/1"
q_profile_entry_data = {
    "configuration": {
        "description": "d1",
        "local_priorities": [1]
    }
}

q_profile_post_url = "/rest/v1/system/q_profiles"
q_profile_url = q_profile_post_url + "/p1"
q_profile_data = {
    "configuration": {
        "name": "n1",
        "q_profile_entries": []
    }
}

qos_cos_map_entry_post_url = "/rest/v1/system/qos_cos_map_entries"
qos_cos_map_entry_url = qos_cos_map_entry_post_url + "/1"
qos_cos_map_entry_data = {
    "configuration": {
        "code_point": 1,
        "color": "green",
        "description": "d1",
        "local_priority": 2
    }
}

qos_dscp_map_entry_post_url = "/rest/v1/system/qos_dscp_map_entries"
qos_dscp_map_entry_url = qos_dscp_map_entry_post_url + "/1"
qos_dscp_map_entry_data = {
    "configuration": {
        "code_point": 1,
        "color": "green",
        "description": "d1",
        "local_priority": 2
    }
}

qos_post_url = "/rest/v1/system/qoss"
qos_url = qos_post_url + "/p1"
qos_data = {
    "configuration": {
        "name": "n1",
        "queues": []
    }
}

queue_post_url = "/rest/v1/system/qoss/p1/queues"
queue_url = queue_post_url + "/1"
queue_data = {
    "configuration": {
        "algorithm": "dwrr",
        "weight": 1
    }
}

system_url = "/rest/v1/system"
system_data = {
    "configuration": {
        "hostname": "",
        "asset_tag_number": "",
        "q_profile": "/rest/v1/system/q_profiles/default",
        "qos": "/rest/v1/system/qoss/default",
        "qos_config": {
            "qos_trust": "dscp"
        },
        "qos_cos_map_entries": [],
        "qos_dscp_map_entries": []
    }
}

def setUp_interface():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('interface {p1}'))
    ops1(format('no apply qos schedule-profile p1'))

def setUp_qosProfiles():
    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('apply qos queue-profile default '
                   'schedule-profile default'))

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

def check_system_qos_status_has(s):
    response_status, response_data = execute_request(
        system_url, "GET",
        None, switch_ip)

    assert s in response_data

def case_port_qos_patch():
    data = [{"op": "add", "path": "/qos_config",
             "value": {"qos_trust": "none"}}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_port_qos_patch_validate_port_cos_has_port_trust_mode_none():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/qos_config",
             "value": {"qos_trust": "cos", "cos_override": "1"}}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS COS override is not currently supported.' in response_data

def case_port_qos_patch_validate_port_dscp_has_port_trust_mode_none():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/qos_config",
             "value": {"qos_trust": "dscp", "dscp_override": "1"}}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS DSCP override is only allowed if' in response_data

def case_port_qos_patch_validate_apply_port_queue_profile_is_null():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/q_profile",
             "value": "/rest/v1/system/q_profiles/p1"}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'Port-level queue profile is not supported.' in response_data

def case_port_qos_patch_validate_apply_port_s_p_has_same_algorithms():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/qos",
             "value": "/rest/v1/system/qoss/p2"}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must have the same algorithm on all queues.' in response_data

def case_port_qos_patch_validate_apply_port_profiles_have_same_queues():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 5'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/qos",
             "value": "/rest/v1/system/qoss/p2"}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

def case_port_qos_put():
    data = deepcopy(port_data)

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_port_qos_put_validate_port_cos_has_trust_mode_none():
    data = deepcopy(port_data)
    data["configuration"]["qos_config"]["cos_override"] = "1"

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS COS override is not currently supported.' in response_data

def case_port_qos_put_port_dscp_with_sys_trust_none_port_trust_dscp():
    ops1(format('qos trust none'))

    data = deepcopy(port_data)
    data["configuration"]["qos_config"] = {
        "qos_trust": "dscp",
        "dscp_override": "1"
    }

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS DSCP override is only allowed if' in response_data

def case_port_qos_put_port_dscp_with_sys_trust_none_port_trust_null():
    ops1(format('qos trust none'))

    data = deepcopy(port_data)
    data["configuration"]["qos_config"] = {
        "dscp_override": "1"
    }

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_port_qos_put_port_dscp_with_sys_trust_dscp_port_trust_none():
    ops1(format('qos trust dscp'))

    data = deepcopy(port_data)
    data["configuration"]["qos_config"] = {
        "qos_trust": "none",
        "dscp_override": "1"
    }

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_port_qos_put_port_dscp_with_sys_trust_dscp_port_trust_null():
    ops1(format('qos trust dscp'))

    data = deepcopy(port_data)
    data["configuration"]["qos_config"] = {
        "dscp_override": "1"
    }

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS DSCP override is only allowed if' in response_data

def case_port_qos_put_validate_apply_port_queue_profile_is_null():
    data = deepcopy(port_data)
    data["configuration"]["q_profile"] = "/rest/v1/system/q_profiles/p1"

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'Port-level queue profile is not supported.' in response_data

def case_port_qos_put_validate_apply_port_s_p_has_same_algorithms():
    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))

    data = deepcopy(port_data)
    data["configuration"]["qos"] = "/rest/v1/system/qoss/p2"

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must have the same algorithm on all queues.' in response_data

def case_port_qos_put_validate_apply_port_profiles_have_same_queues():
    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 5'))
    ops1(format('exit'))

    data = deepcopy(port_data)
    data["configuration"]["qos"] = "/rest/v1/system/qoss/p2"

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

def case_q_profile_entry_post():
    data = deepcopy(q_profile_entry_data)
    data["configuration"]["queue_number"] = "1"

    response_status, response_data = execute_request(
        q_profile_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.CREATED
    assert response_data is ''

def case_q_profile_entry_post_validate_profile_applied_cannot_be_a_or_d():
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = deepcopy(q_profile_entry_data)
    data["configuration"]["queue_number"] = "1"

    response_status, response_data = execute_request(
        q_profile_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_entry_post_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(q_profile_entry_data)
    data["configuration"]["queue_number"] = "1"

    q_profile_entry_post_url = "/rest/v1/system/q_profiles/" + \
        "factory-default/q_profile_entries"

    response_status, response_data = execute_request(
        q_profile_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_entry_post_validate_profile_entry_name_valid_chars():
    setUp_interface()
    setUp_qosProfiles()

    data = deepcopy(q_profile_entry_data)
    data["configuration"]["queue_number"] = "1"
    data["configuration"]["description"] = "name@#$%name"

    response_status, response_data = execute_request(
        q_profile_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_q_profile_entry_patch():
    data = [{"op": "add", "path": "/description", "value": "d1"}]

    response_status, response_data = execute_request(
        q_profile_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_q_profile_entry_patch_validate_profile_applied_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = [{"op": "add", "path": "/description", "value": "d1"}]

    response_status, response_data = execute_request(
        q_profile_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_entry_patch_validate_hw_default_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/description", "value": "d1"}]
    q_profile_entry_url = "/rest/v1/system/q_profiles/" + \
        "factory-default/q_profile_entries/1"

    response_status, response_data = execute_request(
        q_profile_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_entry_patch_validate_profile_entry_name_valid_chars():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/description", "value": "d1%$#@d1"}]

    response_status, response_data = execute_request(
        q_profile_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_q_profile_entry_put():
    data = deepcopy(q_profile_entry_data)

    response_status, response_data = execute_request(
        q_profile_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_q_profile_entry_put_validate_profile_applied_cannot_be_a_or_d():
    setUp_interface()
    setUp_qosProfiles()

    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = deepcopy(q_profile_entry_data)

    response_status, response_data = execute_request(
        q_profile_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_entry_put_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(q_profile_entry_data)
    q_profile_entry_url = "/rest/v1/system/q_profiles/" + \
        "factory-default/q_profile_entries/1"

    response_status, response_data = execute_request(
        q_profile_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_entry_put_validate_profile_entry_name_valid_chars():
    setUp_interface()
    setUp_qosProfiles()

    data = deepcopy(q_profile_entry_data)
    data["configuration"]["description"] = "name@#$%name"

    response_status, response_data = execute_request(
        q_profile_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_q_profile_entry_delete():
    case_q_profile_entry_put()

    response_status, response_data = execute_request(
        q_profile_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_q_profile_entry_delete_validate_profile_applied_cannot_be_a_or_d():
    setUp_interface()
    setUp_qosProfiles()

    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    response_status, response_data = execute_request(
        q_profile_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_entry_delete_validate_profile_hw_def_cannot_be_a_or_d():
    data = deepcopy(q_profile_entry_data)
    q_profile_entry_url = "/rest/v1/system/q_profiles/" + \
        "factory-default/q_profile_entries/1"

    response_status, response_data = execute_request(
        q_profile_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_post():
    data = deepcopy(q_profile_data)
    data["configuration"]["name"] = "n1"

    response_status, response_data = execute_request(
        q_profile_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.CREATED
    assert response_data is ''

def case_q_profile_post_validate_profile_name_contains_valid_chars():
    data = deepcopy(q_profile_data)
    data["configuration"]["name"] = "name@#$%name"

    response_status, response_data = execute_request(
        q_profile_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_q_profile_post_validate_profile_name_cannot_be_strict():
    data = deepcopy(q_profile_data)
    data["configuration"]["name"] = "strict"

    response_status, response_data = execute_request(
        q_profile_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The profile name cannot be \'strict\'.' in response_data

def case_q_profile_patch():
    setUp_interface()
    setUp_qosProfiles()

    data = [{"op": "add", "path": "/q_profile_entries", "value": []}]

    response_status, response_data = execute_request(
        q_profile_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_q_profile_patch_validate_profile_applied_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = [{"op": "add", "path": "/q_profile_entries", "value": []}]

    response_status, response_data = execute_request(
        q_profile_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_patch_validate_profile_hw_default_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/q_profile_entries", "value": []}]
    q_profile_url = "/rest/v1/system/q_profiles/factory-default"

    response_status, response_data = execute_request(
        q_profile_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_put():
    setUp_interface()
    setUp_qosProfiles()

    data = deepcopy(q_profile_data)

    response_status, response_data = execute_request(
        q_profile_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_q_profile_put_validate_profile_applied_cannot_be_a_or_d():
    setUp_interface()
    setUp_qosProfiles()

    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = deepcopy(q_profile_data)

    response_status, response_data = execute_request(
        q_profile_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_put_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(q_profile_data)
    q_profile_url = "/rest/v1/system/q_profiles/factory-default"

    response_status, response_data = execute_request(
        q_profile_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_delete():
    case_q_profile_put()

    response_status, response_data = execute_request(
        q_profile_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.NO_CONTENT or \
        response_status == http.client.OK
    assert response_data is ''

def case_q_profile_delete_validate_profile_applied_cannot_be_a_or_d():
    setUp_interface()
    setUp_qosProfiles()

    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    response_status, response_data = execute_request(
        q_profile_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_delete_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(q_profile_data)
    q_profile_url = "/rest/v1/system/q_profiles/factory-default"

    response_status, response_data = execute_request(
        q_profile_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_delete_validate_profile_default_cannot_be_deleted():
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = deepcopy(q_profile_data)
    q_profile_url = "/rest/v1/system/q_profiles/default"

    response_status, response_data = execute_request(
        q_profile_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The default profile cannot be deleted.' in response_data

def case_qos_cos_map_entry_post():
    data = deepcopy(qos_cos_map_entry_data)

    response_status, response_data = execute_request(
        qos_cos_map_entry_post_url, "POST",
        None, switch_ip)

    assert response_status == http.client.LENGTH_REQUIRED

def case_qos_cos_map_entry_patch():
    data = [{"op": "add", "path": "/description", "value": "d1"}]

    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_qos_cos_map_entry_patch_validate_cos_map_desc_has_valid_chars():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/description", "value": "d1%$#@d1"}]

    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_cos_map_entry_put():
    data = deepcopy(qos_cos_map_entry_data)

    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_qos_cos_map_entry_put_validate_cos_map_desc_has_valid_chars():
    data = deepcopy(qos_cos_map_entry_data)
    data["configuration"]["description"] = "name@#$%name"

    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_cos_map_entry_delete():
    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'COS Map Entries cannot be deleted.' in response_data

def case_qos_dscp_map_entry_post():
    data = deepcopy(qos_dscp_map_entry_data)

    response_status, response_data = execute_request(
        qos_dscp_map_entry_post_url, "POST",
        None, switch_ip)

    assert response_status == http.client.LENGTH_REQUIRED

def case_qos_dscp_map_entry_patch():
    data = [{"op": "add", "path": "/description", "value": "d1"}]

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_qos_dscp_map_entry_patch_validate_dscp_map_desc_has_valid_chars():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/description", "value": "d1%$#@d1"}]

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_dscp_map_entry_patch_validate_pcp_is_empty():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/priority_code_point",
             "value": "1"}]

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'not supported.' in response_data

def case_qos_dscp_map_entry_put():
    data = deepcopy(qos_dscp_map_entry_data)

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_qos_dscp_map_entry_put_validate_dscp_map_desc_has_valid_chars():
    data = deepcopy(qos_dscp_map_entry_data)
    data["configuration"]["description"] = "name@#$%name"

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_dscp_map_entry_put_validate_pcp_is_empty():
    data = deepcopy(qos_dscp_map_entry_data)
    data["configuration"]["priority_code_point"] = 1

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'not currently supported' in response_data

def case_qos_dscp_map_entry_delete():
    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'DSCP Map Entries cannot be deleted.' in response_data

def case_qos_post():
    data = deepcopy(qos_data)
    data["configuration"]["name"] = "n1"

    response_status, response_data = execute_request(
        qos_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.CREATED
    assert response_data is ''

def case_qos_post_validate_profile_name_contains_valid_chars():
    data = deepcopy(qos_data)
    data["configuration"]["name"] = "name@#$%name"

    response_status, response_data = execute_request(
        qos_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_post_validate_profile_name_cannot_be_strict():
    data = deepcopy(qos_data)
    data["configuration"]["name"] = "strict"

    response_status, response_data = execute_request(
        qos_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The profile name cannot be \'strict\'.' in response_data

def case_qos_patch():
    setUp_interface()
    setUp_qosProfiles()

    data = [{"op": "add", "path": "/queues", "value": []}]

    response_status, response_data = execute_request(
        qos_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_qos_patch_validate_profile_applied_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = [{"op": "add", "path": "/queues", "value": []}]

    response_status, response_data = execute_request(
        qos_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_qos_patch_validate_profile_hw_default_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/queues", "value": []}]
    qos_url = "/rest/v1/system/qoss/factory-default"

    response_status, response_data = execute_request(
        qos_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_qos_put():
    setUp_interface()
    setUp_qosProfiles()

    data = deepcopy(qos_data)

    response_status, response_data = execute_request(
        qos_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_qos_put_validate_profile_applied_cannot_be_a_or_d():
    setUp_interface()
    setUp_qosProfiles()

    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = deepcopy(qos_data)

    response_status, response_data = execute_request(
        qos_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_qos_put_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(qos_data)
    qos_url = "/rest/v1/system/qoss/factory-default"

    response_status, response_data = execute_request(
        qos_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_qos_delete():
    case_qos_put()

    response_status, response_data = execute_request(
        qos_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.NO_CONTENT or \
        response_status == http.client.OK
    assert response_data is ''

def case_qos_delete_validate_profile_applied_cannot_be_a_or_d():
    setUp_interface()
    setUp_qosProfiles()

    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    response_status, response_data = execute_request(
        qos_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_qos_delete_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(qos_data)
    qos_url = "/rest/v1/system/qoss/factory-default"

    response_status, response_data = execute_request(
        qos_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_qos_delete_validate_profile_default_cannot_be_deleted():
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = deepcopy(qos_data)
    qos_url = "/rest/v1/system/qoss/default"

    response_status, response_data = execute_request(
        qos_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The default profile cannot be deleted.' in response_data

def case_queue_post():
    setUp_interface()
    setUp_qosProfiles()

    data = deepcopy(queue_data)
    data["configuration"]["queue_number"] = "1"

    response_status, response_data = execute_request(
        queue_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.CREATED
    assert response_data is ''

def case_queue_post_validate_profile_applied_cannot_be_a_or_d():
    setUp_interface()
    setUp_qosProfiles()

    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = deepcopy(queue_data)
    data["configuration"]["queue_number"] = "1"

    response_status, response_data = execute_request(
        queue_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_queue_post_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(queue_data)
    data["configuration"]["queue_number"] = "1"
    queue_post_url = "/rest/v1/system/qoss/factory-default/queues"

    response_status, response_data = execute_request(
        queue_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_queue_post_validate_profile_entry_with_dwrr_has_w_less_than_max_w():
    setUp_interface()
    setUp_qosProfiles()

    data = deepcopy(queue_data)
    data["configuration"]["queue_number"] = "1"
    data["configuration"]["weight"] = 1024

    response_status, response_data = execute_request(
        queue_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The weight cannot be larger than' in response_data

def case_queue_patch():
    data = [{"op": "add", "path": "/weight", "value": 1}]

    response_status, response_data = execute_request(
        queue_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_queue_patch_validate_profile_applied_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = [{"op": "add", "path": "/weight", "value": 1}]

    response_status, response_data = execute_request(
        queue_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_queue_patch_validate_profile_hw_default_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/weight", "value": 1}]
    queue_url = "/rest/v1/system/qoss/factory-default/queues"

    response_status, response_data = execute_request(
        queue_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_queue_patch_validate_profile_entry_with_dwrr_has_w_less_than_max_w():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/weight", "value": 1024}]

    response_status, response_data = execute_request(
        queue_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The weight cannot be larger than' in response_data

def case_queue_put():
    data = deepcopy(queue_data)

    response_status, response_data = execute_request(
        queue_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_queue_put_validate_profile_applied_cannot_be_a_or_d():
    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    data = deepcopy(queue_data)

    response_status, response_data = execute_request(
        queue_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_queue_put_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(queue_data)
    queue_url = "/rest/v1/system/qoss/factory-default/queues/1"

    response_status, response_data = execute_request(
        queue_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_queue_put_validate_profile_entry_with_dwrr_has_w_less_than_max_w():
    setUp_interface()
    setUp_qosProfiles()

    data = deepcopy(queue_data)
    data["configuration"]["weight"] = 1024

    response_status, response_data = execute_request(
        queue_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The weight cannot be larger than' in response_data

def case_queue_delete():
    case_queue_put()

    response_status, response_data = execute_request(
        queue_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_queue_delete_validate_profile_applied_cannot_be_a_or_d():
    setUp_interface()
    setUp_qosProfiles()

    ops1(format('apply qos queue-profile p1 schedule-profile p1'))

    response_status, response_data = execute_request(
        queue_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_queue_delete_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(queue_data)
    queue_url = "/rest/v1/system/qoss/factory-default/queues/1"

    response_status, response_data = execute_request(
        queue_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_system_qos_patch():
    setUp_interface()
    setUp_qosProfiles()

    data = [{"op": "add", "path": "/qos_config",
             "value": {"qos_trust": "dscp"}}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_trust_global_is_not_empty():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/qos_config",
             "value": {}}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The qos trust value cannot be empty.' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_global_q_p_has_all_local_p():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos queue-profile p2'))
    ops1(format('qos queue-profile p2'))
    ops1(format('map queue 4 local-priority 4'))
    ops1(format('map queue 5 local-priority 5'))
    ops1(format('map queue 6 local-priority 6'))
    ops1(format('map queue 7 local-priority 7'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 1 local-priority 1'))
    ops1(format('map queue 2 local-priority 2'))
    ops1(format('name queue 3 n1'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/q_profile",
             "value": "/rest/v1/system/q_profiles/p2"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The queue profile is missing local priority' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_global_q_p_has_no_dup_local_p():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos queue-profile p2'))
    ops1(format('qos queue-profile p2'))
    ops1(format('map queue 4 local-priority 4'))
    ops1(format('map queue 5 local-priority 5'))
    ops1(format('map queue 6 local-priority 6'))
    ops1(format('map queue 7 local-priority 7'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 1 local-priority 1'))
    ops1(format('map queue 2 local-priority 2'))
    ops1(format('map queue 3 local-priority 3'))
    ops1(format('map queue 3 local-priority 4'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/q_profile",
             "value": "/rest/v1/system/q_profiles/p2"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'assigned more than once' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_global_s_p_has_all_same_alg():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/qos",
             "value": "/rest/v1/system/qoss/p2"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must have the same algorithm on all queues.' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_global_profiles_have_same_queues():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 5'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/qos",
             "value": "/rest/v1/system/qoss/p2"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_port_profiles_have_same_queues():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
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
    data = [{"op": "add", "path": "/q_profile",
             "value": "/rest/v1/system/q_profiles/default"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put():
    data = deepcopy(system_data)

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_trust_global_is_not_empty():
    data = deepcopy(system_data)
    data["configuration"]["qos_config"] = {}

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The qos trust value cannot be empty.' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_global_q_p_has_all_local_p():
    ops1(format('no qos queue-profile p2'))
    ops1(format('qos queue-profile p2'))
    ops1(format('map queue 4 local-priority 4'))
    ops1(format('map queue 5 local-priority 5'))
    ops1(format('map queue 6 local-priority 6'))
    ops1(format('map queue 7 local-priority 7'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 1 local-priority 1'))
    ops1(format('map queue 2 local-priority 2'))
    ops1(format('name queue 3 n1'))
    ops1(format('exit'))

    data = deepcopy(system_data)
    data["configuration"]["q_profile"] = "/rest/v1/system/q_profiles/p2"

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The queue profile is missing local priority' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_global_q_p_has_no_dup_local_p():
    ops1(format('no qos queue-profile p2'))
    ops1(format('qos queue-profile p2'))
    ops1(format('map queue 4 local-priority 4'))
    ops1(format('map queue 5 local-priority 5'))
    ops1(format('map queue 6 local-priority 6'))
    ops1(format('map queue 7 local-priority 7'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 1 local-priority 1'))
    ops1(format('map queue 2 local-priority 2'))
    ops1(format('map queue 3 local-priority 3'))
    ops1(format('map queue 3 local-priority 4'))
    ops1(format('exit'))

    data = deepcopy(system_data)
    data["configuration"]["q_profile"] = "/rest/v1/system/q_profiles/p2"

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'assigned more than once' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_global_s_p_has_all_same_algorithms():
    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))

    data = deepcopy(system_data)
    data["configuration"]["qos"] = "/rest/v1/system/qoss/p2"

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must have the same algorithm on all queues.' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_global_profiles_have_same_queues():
    ops1(format('no qos schedule-profile p2'))
    ops1(format('qos schedule-profile p2'))
    ops1(format('strict queue 5'))
    ops1(format('exit'))

    data = deepcopy(system_data)
    data["configuration"]["qos"] = "/rest/v1/system/qoss/p2"

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_port_profiles_have_same_queues():
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
    data = deepcopy(system_data)

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

    check_system_qos_status_has("\"queue_profile\": \"p2\"")
    check_system_qos_status_has("\"schedule_profile\": \"p2\"")

def test_qos_ct_rest_custom_validators(topology, setup):
    setUp_interface()
    setUp_qosProfiles()

    case_port_qos_patch()
    case_port_qos_patch_validate_port_cos_has_port_trust_mode_none()
    case_port_qos_patch_validate_port_dscp_has_port_trust_mode_none()
    case_port_qos_patch_validate_apply_port_queue_profile_is_null()
    case_port_qos_patch_validate_apply_port_s_p_has_same_algorithms()
    case_port_qos_patch_validate_apply_port_profiles_have_same_queues()
    case_port_qos_put()
    case_port_qos_put_validate_port_cos_has_trust_mode_none()
    case_port_qos_put_port_dscp_with_sys_trust_none_port_trust_dscp()
    case_port_qos_put_port_dscp_with_sys_trust_none_port_trust_null()
    case_port_qos_put_port_dscp_with_sys_trust_dscp_port_trust_none()
    case_port_qos_put_port_dscp_with_sys_trust_dscp_port_trust_null()
    case_port_qos_put_validate_apply_port_queue_profile_is_null()
    case_port_qos_put_validate_apply_port_s_p_has_same_algorithms()
    case_port_qos_put_validate_apply_port_profiles_have_same_queues()

    case_q_profile_entry_post()
    case_q_profile_entry_post_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_entry_post_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_entry_post_validate_profile_entry_name_valid_chars()
    case_q_profile_entry_patch()
    case_q_profile_entry_patch_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_entry_patch_validate_hw_default_cannot_be_a_or_d()
    case_q_profile_entry_patch_validate_profile_entry_name_valid_chars()
    case_q_profile_entry_put()
    case_q_profile_entry_put_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_entry_put_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_entry_put_validate_profile_entry_name_valid_chars()
    case_q_profile_entry_delete()
    case_q_profile_entry_delete_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_entry_delete_validate_profile_hw_def_cannot_be_a_or_d()

    case_q_profile_post()
    case_q_profile_post_validate_profile_name_contains_valid_chars()
    case_q_profile_post_validate_profile_name_cannot_be_strict()
    case_q_profile_patch()
    case_q_profile_patch_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_patch_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_put()
    case_q_profile_put_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_put_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_delete()
    case_q_profile_delete_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_delete_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_delete_validate_profile_default_cannot_be_deleted()

    case_qos_cos_map_entry_post()
    case_qos_cos_map_entry_patch()
    case_qos_cos_map_entry_patch_validate_cos_map_desc_has_valid_chars()
    case_qos_cos_map_entry_put()
    case_qos_cos_map_entry_put_validate_cos_map_desc_has_valid_chars()
    case_qos_cos_map_entry_delete()

    case_qos_dscp_map_entry_post()
    case_qos_dscp_map_entry_patch()
    case_qos_dscp_map_entry_patch_validate_dscp_map_desc_has_valid_chars()
    case_qos_dscp_map_entry_patch_validate_pcp_is_empty()
    case_qos_dscp_map_entry_put()
    case_qos_dscp_map_entry_put_validate_dscp_map_desc_has_valid_chars()
    case_qos_dscp_map_entry_put_validate_pcp_is_empty()
    case_qos_dscp_map_entry_delete()

    case_qos_post()
    case_qos_post_validate_profile_name_contains_valid_chars()
    case_qos_post_validate_profile_name_cannot_be_strict()
    case_qos_patch()
    case_qos_patch_validate_profile_applied_cannot_be_a_or_d()
    case_qos_patch_validate_profile_hw_default_cannot_be_a_or_d()
    case_qos_put()
    case_qos_put_validate_profile_applied_cannot_be_a_or_d()
    case_qos_put_validate_profile_hw_default_cannot_be_a_or_d()
    case_qos_delete()
    case_qos_delete_validate_profile_applied_cannot_be_a_or_d()
    case_qos_delete_validate_profile_hw_default_cannot_be_a_or_d()
    case_qos_delete_validate_profile_default_cannot_be_deleted()

    case_queue_post()
    case_queue_post_validate_profile_applied_cannot_be_a_or_d()
    case_queue_post_validate_profile_hw_default_cannot_be_a_or_d()
    case_queue_post_validate_profile_entry_with_dwrr_has_w_less_than_max_w()
    case_queue_patch()
    case_queue_patch_validate_profile_applied_cannot_be_a_or_d()
    case_queue_patch_validate_profile_hw_default_cannot_be_a_or_d()
    case_queue_patch_validate_profile_entry_with_dwrr_has_w_less_than_max_w()
    case_queue_put()
    case_queue_put_validate_profile_applied_cannot_be_a_or_d()
    case_queue_put_validate_profile_hw_default_cannot_be_a_or_d()
    case_queue_put_validate_profile_entry_with_dwrr_has_w_less_than_max_w()
    case_queue_delete()
    case_queue_delete_validate_profile_applied_cannot_be_a_or_d()
    case_queue_delete_validate_profile_hw_default_cannot_be_a_or_d()

    case_system_qos_patch()
    case_system_qos_patch_validate_trust_global_is_not_empty()
    case_system_qos_patch_validate_apply_global_q_p_has_all_local_p()
    case_system_qos_patch_validate_apply_global_q_p_has_no_dup_local_p()
    case_system_qos_patch_validate_apply_global_s_p_has_all_same_alg()
    case_system_qos_patch_validate_apply_global_profiles_have_same_queues()
    case_system_qos_patch_validate_apply_port_profiles_have_same_queues()
    case_system_qos_put()
    case_system_qos_put_validate_trust_global_is_not_empty()
    case_system_qos_put_validate_apply_global_q_p_has_all_local_p()
    case_system_qos_put_validate_apply_global_q_p_has_no_dup_local_p()
    case_system_qos_put_validate_apply_global_s_p_has_all_same_algorithms()
    case_system_qos_put_validate_apply_global_profiles_have_same_queues()
    case_system_qos_put_validate_apply_port_profiles_have_same_queues()
