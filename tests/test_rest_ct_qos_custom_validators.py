#!/usr/bin/python

# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
#
# GNU Zebra is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# GNU Zebra is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Zebra; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

from opsvsi.docker import *
from opsvsi.opsvsitest import *
import re

import pytest
from copy import deepcopy
import time

import json
import httplib
import urllib

from utils.fakes import *
from utils.utils import *

port_url = "/rest/v1/system/ports/1"
port_data = {
    "configuration": {
        "qos": "/rest/v1/system/qoss/p1",
        "qos_config": {
            "qos_trust": "none",
            "dscp_override": "1"
        }
    }
}

q_profile_entry_url = "/rest/v1/system/q_profiles/p1/q_profile_entries/1"
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

qos_cos_map_entry_url = "/rest/v1/system/qos_cos_map_entries/1"
qos_cos_map_entry_data = {
    "configuration": {
        "code_point": 1,
        "color": "green",
        "description": "d1",
        "local_priority": 2
    }
}

qos_dscp_map_entry_url = "/rest/v1/system/qos_dscp_map_entries/1"
qos_dscp_map_entry_data = {
    "configuration": {
        "code_point": 1,
        "color": "green",
        "description": "d1",
        "local_priority": 2,
        "priority_code_point": 3
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

queue_url = "/rest/v1/system/qoss/p1/queues/1"
queue_data = {
    "configuration": {
        "algorithm": "wrr",
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

class QosRestCustomValidatorsTest(OpsVsiTest):
    def setupNet(self):
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        topo = SingleSwitchTopo(k=0, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(topo, switch=VsiOpenSwitch,
                           host=Host, link=OpsVsiLink,
                           controller=None, build=True)

class Test_qos_rest_custom_validators:
    def setup_class(cls):
        Test_qos_rest_custom_validators.test = QosRestCustomValidatorsTest()

        # Allow restd time to start.
        time.sleep(2)

    def teardown_class(cls):
        Test_qos_rest_custom_validators.test.net.stop()

    def setup(self):
        self.s1 = Test_qos_rest_custom_validators.test.net.switches[0]
        self.switch_ip = get_switch_ip(self.s1)

        self.setUp_interface()
        self.setUp_qosProfiles()

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def setUp_interface(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('no apply qos schedule-profile p1')

    def setUp_qosProfiles(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('apply qos queue-profile default schedule-profile default')

        self.s1.cmdCLI('no qos queue-profile p1')
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('map queue 4 local-priority 3')
        self.s1.cmdCLI('map queue 5 local-priority 2')
        self.s1.cmdCLI('map queue 6 local-priority 1')
        self.s1.cmdCLI('map queue 7 local-priority 0')
        self.s1.cmdCLI('map queue 0 local-priority 7')
        self.s1.cmdCLI('map queue 1 local-priority 6')
        self.s1.cmdCLI('map queue 2 local-priority 5')
        self.s1.cmdCLI('map queue 3 local-priority 4')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('no qos schedule-profile p1')
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 4 weight 40')
        self.s1.cmdCLI('wrr queue 5 weight 50')
        self.s1.cmdCLI('wrr queue 6 weight 60')
        self.s1.cmdCLI('wrr queue 7 weight 70')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')

    def teardown(self):
        pass

    def __del__(self):
        del self.test

    def test_port_qos_put(self):
        data = deepcopy(port_data)

        response_status, response_data = execute_request(
            port_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.OK
        assert response_data is ''

    def test_port_qos_put_validate_port_cos_override_has_port_trust_mode_none(self):
        data = deepcopy(port_data)
        data["configuration"]["qos_config"]["cos_override"] = "1"

        response_status, response_data = execute_request(
            port_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'QoS COS override is not currently supported.' in response_data

    def test_port_qos_put_validate_port_dscp_override_has_port_trust_mode_none(self):
        data = deepcopy(port_data)
        data["configuration"]["qos_config"]["qos_trust"] = "dscp"

        response_status, response_data = execute_request(
            port_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'QoS DSCP override is only allowed if' in response_data

    def test_port_qos_put_validate_apply_port_queue_profile_is_null(self):
        data = deepcopy(port_data)
        data["configuration"]["q_profile"] = "/rest/v1/system/q_profiles/p1"

        response_status, response_data = execute_request(
            port_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'Port-level queue profile is not supported.' in response_data

    def test_port_qos_put_validate_apply_port_schedule_profile_has_same_algorithm_on_all_queues(self):
        self.s1.cmdCLI('no qos schedule-profile p2')
        self.s1.cmdCLI('qos schedule-profile p2')
        self.s1.cmdCLI('strict queue 4')
        self.s1.cmdCLI('strict queue 5')
        self.s1.cmdCLI('strict queue 6')
        self.s1.cmdCLI('strict queue 7')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')

        data = deepcopy(port_data)
        data["configuration"]["qos"] = "/rest/v1/system/qoss/p2"

        response_status, response_data = execute_request(
            port_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'must have the same algorithm on all queues.' in response_data

    def test_port_qos_put_validate_apply_port_profiles_contain_same_queues(self):
        self.s1.cmdCLI('no qos schedule-profile p2')
        self.s1.cmdCLI('qos schedule-profile p2')
        self.s1.cmdCLI('strict queue 5')
        self.s1.cmdCLI('exit')

        data = deepcopy(port_data)
        data["configuration"]["qos"] = "/rest/v1/system/qoss/p2"

        response_status, response_data = execute_request(
            port_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'must contain all of the' in response_data

    def test_q_profile_entry_put(self):
        data = deepcopy(q_profile_entry_data)

        response_status, response_data = execute_request(
            q_profile_entry_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.OK
        assert response_data is ''

    def test_q_profile_entry_put_validate_profile_applied_cannot_be_amended_or_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        data = deepcopy(q_profile_entry_data)

        response_status, response_data = execute_request(
            q_profile_entry_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'An applied profile cannot' in response_data

    def test_q_profile_entry_put_validate_profile_hw_default_cannot_be_amended_or_deleted(self):
        data = deepcopy(q_profile_entry_data)
        q_profile_entry_url = "/rest/v1/system/q_profiles/factory-default/q_profile_entries/1"

        response_status, response_data = execute_request(
            q_profile_entry_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'A hardware default profile cannot' in response_data

    def test_q_profile_entry_put_validate_profile_entry_name_contains_valid_chars(self):
        data = deepcopy(q_profile_entry_data)
        data["configuration"]["description"] = "name@#$%name"

        response_status, response_data = execute_request(
            q_profile_entry_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The allowed characters are' in response_data

    def test_q_profile_entry_delete(self):
        self.test_q_profile_entry_put()

        response_status, response_data = execute_request(
            q_profile_entry_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.NO_CONTENT
        assert response_data is ''

    def test_q_profile_entry_delete_validate_profile_applied_cannot_be_amended_or_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        response_status, response_data = execute_request(
            q_profile_entry_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'An applied profile cannot' in response_data

    def test_q_profile_entry_delete_validate_profile_hw_default_cannot_be_amended_or_deleted(self):
        data = deepcopy(q_profile_entry_data)
        q_profile_entry_url = "/rest/v1/system/q_profiles/factory-default/q_profile_entries/1"

        response_status, response_data = execute_request(
            q_profile_entry_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'A hardware default profile cannot' in response_data

    def test_q_profile_put(self):
        data = deepcopy(q_profile_data)

        response_status, response_data = execute_request(
            q_profile_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.OK
        assert response_data is ''

    def test_q_profile_put_validate_profile_applied_cannot_be_amended_or_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        data = deepcopy(q_profile_data)

        response_status, response_data = execute_request(
            q_profile_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'An applied profile cannot' in response_data

    def test_q_profile_put_validate_profile_hw_default_cannot_be_amended_or_deleted(self):
        data = deepcopy(q_profile_data)
        q_profile_url = "/rest/v1/system/q_profiles/factory-default"

        response_status, response_data = execute_request(
            q_profile_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'A hardware default profile cannot' in response_data

    def test_q_profile_post(self):
        data = deepcopy(q_profile_data)
        data["configuration"]["name"] = "n1"

        response_status, response_data = execute_request(
            q_profile_post_url, "POST",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.CREATED
        assert response_data is ''

    def test_q_profile_post_validate_profile_name_contains_valid_chars(self):
        data = deepcopy(q_profile_data)
        data["configuration"]["name"] = "name@#$%name"

        response_status, response_data = execute_request(
            q_profile_post_url, "POST",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The allowed characters are' in response_data

    def test_q_profile_post_validate_profile_name_cannot_be_strict(self):
        data = deepcopy(q_profile_data)
        data["configuration"]["name"] = "strict"

        response_status, response_data = execute_request(
            q_profile_post_url, "POST",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The profile name cannot be \'strict\'.' in response_data

    def test_q_profile_delete(self):
        self.test_q_profile_put()

        response_status, response_data = execute_request(
            q_profile_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.NO_CONTENT or \
            response_status == httplib.OK
        assert response_data is ''

    def test_q_profile_delete_validate_profile_applied_cannot_be_amended_or_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        response_status, response_data = execute_request(
            q_profile_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'An applied profile cannot' in response_data

    def test_q_profile_delete_validate_profile_hw_default_cannot_be_amended_or_deleted(self):
        data = deepcopy(q_profile_data)
        q_profile_url = "/rest/v1/system/q_profiles/factory-default"

        response_status, response_data = execute_request(
            q_profile_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'A hardware default profile cannot' in response_data

    def test_q_profile_delete_validate_profile_default_cannot_be_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        data = deepcopy(q_profile_data)
        q_profile_url = "/rest/v1/system/q_profiles/default"

        response_status, response_data = execute_request(
            q_profile_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The default profile cannot be deleted.' in response_data

    def test_qos_cos_map_entry_put(self):
        data = deepcopy(qos_cos_map_entry_data)

        response_status, response_data = execute_request(
            qos_cos_map_entry_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.OK
        assert response_data is ''

    def test_qos_cos_map_entry_put_validate_cos_map_description_contains_valid_chars(self):
        data = deepcopy(qos_cos_map_entry_data)
        data["configuration"]["description"] = "name@#$%name"

        response_status, response_data = execute_request(
            qos_cos_map_entry_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The allowed characters are' in response_data

    def test_qos_cos_map_entry_delete(self):
        response_status, response_data = execute_request(
            qos_cos_map_entry_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'COS Map Entries cannot be deleted.' in response_data

    def test_qos_dscp_map_entry_put(self):
        data = deepcopy(qos_dscp_map_entry_data)

        response_status, response_data = execute_request(
            qos_dscp_map_entry_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.OK
        assert response_data is ''

    def test_qos_dscp_map_entry_put_validate_dscp_map_description_contains_valid_chars(self):
        data = deepcopy(qos_dscp_map_entry_data)
        data["configuration"]["description"] = "name@#$%name"

        response_status, response_data = execute_request(
            qos_dscp_map_entry_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The allowed characters are' in response_data

    def test_qos_dscp_map_entry_delete(self):
        response_status, response_data = execute_request(
            qos_dscp_map_entry_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'DSCP Map Entries cannot be deleted.' in response_data

    def test_qos_put(self):
        data = deepcopy(qos_data)

        response_status, response_data = execute_request(
            qos_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.OK
        assert response_data is ''

    def test_qos_put_validate_profile_applied_cannot_be_amended_or_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        data = deepcopy(qos_data)

        response_status, response_data = execute_request(
            qos_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'An applied profile cannot' in response_data

    def test_qos_put_validate_profile_hw_default_cannot_be_amended_or_deleted(self):
        data = deepcopy(qos_data)
        qos_url = "/rest/v1/system/qoss/factory-default"

        response_status, response_data = execute_request(
            qos_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'A hardware default profile cannot' in response_data

    def test_qos_post(self):
        data = deepcopy(qos_data)
        data["configuration"]["name"] = "n1"

        response_status, response_data = execute_request(
            qos_post_url, "POST",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.CREATED
        assert response_data is ''

    def test_qos_post_validate_profile_name_contains_valid_chars(self):
        data = deepcopy(qos_data)
        data["configuration"]["name"] = "name@#$%name"

        response_status, response_data = execute_request(
            qos_post_url, "POST",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The allowed characters are' in response_data

    def test_qos_post_validate_profile_name_cannot_be_strict(self):
        data = deepcopy(qos_data)
        data["configuration"]["name"] = "strict"

        response_status, response_data = execute_request(
            qos_post_url, "POST",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The profile name cannot be \'strict\'.' in response_data

    def test_qos_delete(self):
        self.test_qos_put()

        response_status, response_data = execute_request(
            qos_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.NO_CONTENT or \
            response_status == httplib.OK
        assert response_data is ''

    def test_qos_delete_validate_profile_applied_cannot_be_amended_or_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        response_status, response_data = execute_request(
            qos_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'An applied profile cannot' in response_data

    def test_qos_delete_validate_profile_hw_default_cannot_be_amended_or_deleted(self):
        data = deepcopy(qos_data)
        qos_url = "/rest/v1/system/qoss/factory-default"

        response_status, response_data = execute_request(
            qos_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'A hardware default profile cannot' in response_data

    def test_qos_delete_validate_profile_default_cannot_be_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        data = deepcopy(qos_data)
        qos_url = "/rest/v1/system/qoss/default"

        response_status, response_data = execute_request(
            qos_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The default profile cannot be deleted.' in response_data

    def test_queue_put(self):
        data = deepcopy(queue_data)

        response_status, response_data = execute_request(
            queue_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.OK
        assert response_data is ''

    def test_queue_put_validate_profile_applied_cannot_be_amended_or_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        data = deepcopy(queue_data)

        response_status, response_data = execute_request(
            queue_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'An applied profile cannot' in response_data

    def test_queue_put_validate_profile_hw_default_cannot_be_amended_or_deleted(self):
        data = deepcopy(queue_data)
        queue_url = "/rest/v1/system/qoss/factory-default/queues/1"

        response_status, response_data = execute_request(
            queue_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'A hardware default profile cannot' in response_data

    def test_queue_put_validate_profile_entry_with_wrr_has_weight_less_than_max_weight(self):
        data = deepcopy(queue_data)
        data["configuration"]["weight"] = 1024

        response_status, response_data = execute_request(
            queue_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The weight cannot be larger than' in response_data

    def test_queue_delete(self):
        self.test_queue_put()

        response_status, response_data = execute_request(
            queue_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.NO_CONTENT
        assert response_data is ''

    def test_queue_delete_validate_profile_applied_cannot_be_amended_or_deleted(self):
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')

        response_status, response_data = execute_request(
            queue_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'An applied profile cannot' in response_data

    def test_queue_delete_validate_profile_hw_default_cannot_be_amended_or_deleted(self):
        data = deepcopy(queue_data)
        queue_url = "/rest/v1/system/qoss/factory-default/queues/1"

        response_status, response_data = execute_request(
            queue_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'A hardware default profile cannot' in response_data

    def test_system_qos_put(self):
        data = deepcopy(system_data)

        response_status, response_data = execute_request(
            system_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.OK
        assert response_data is ''

    def test_system_qos_put_validate_trust_global_is_not_empty(self):
        data = deepcopy(system_data)
        data["configuration"]["qos_config"] = {}

        response_status, response_data = execute_request(
            system_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The qos trust value cannot be empty.' in response_data

    def test_system_qos_put_validate_apply_global_queue_profile_has_all_local_priorities(self):
        self.s1.cmdCLI('no qos queue-profile p2')
        self.s1.cmdCLI('qos queue-profile p2')
        self.s1.cmdCLI('map queue 4 local-priority 4')
        self.s1.cmdCLI('map queue 5 local-priority 5')
        self.s1.cmdCLI('map queue 6 local-priority 6')
        self.s1.cmdCLI('map queue 7 local-priority 7')
        self.s1.cmdCLI('map queue 0 local-priority 0')
        self.s1.cmdCLI('map queue 1 local-priority 1')
        self.s1.cmdCLI('map queue 2 local-priority 2')
        self.s1.cmdCLI('name queue 3 n1')
        self.s1.cmdCLI('exit')

        data = deepcopy(system_data)
        data["configuration"]["q_profile"] = "/rest/v1/system/q_profiles/p2"

        response_status, response_data = execute_request(
            system_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'The queue profile is missing local priority' in response_data

    def test_system_qos_put_validate_apply_global_queue_profile_has_no_duplicate_local_priorities(self):
        self.s1.cmdCLI('no qos queue-profile p2')
        self.s1.cmdCLI('qos queue-profile p2')
        self.s1.cmdCLI('map queue 4 local-priority 4')
        self.s1.cmdCLI('map queue 5 local-priority 5')
        self.s1.cmdCLI('map queue 6 local-priority 6')
        self.s1.cmdCLI('map queue 7 local-priority 7')
        self.s1.cmdCLI('map queue 0 local-priority 0')
        self.s1.cmdCLI('map queue 1 local-priority 1')
        self.s1.cmdCLI('map queue 2 local-priority 2')
        self.s1.cmdCLI('map queue 3 local-priority 3')
        self.s1.cmdCLI('map queue 3 local-priority 4')
        self.s1.cmdCLI('exit')

        data = deepcopy(system_data)
        data["configuration"]["q_profile"] = "/rest/v1/system/q_profiles/p2"

        response_status, response_data = execute_request(
            system_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'assigned more than once' in response_data

    def test_system_qos_put_validate_apply_global_schedule_profile_has_same_algorithm_on_all_queues(self):
        self.s1.cmdCLI('no qos schedule-profile p2')
        self.s1.cmdCLI('qos schedule-profile p2')
        self.s1.cmdCLI('strict queue 4')
        self.s1.cmdCLI('strict queue 5')
        self.s1.cmdCLI('strict queue 6')
        self.s1.cmdCLI('strict queue 7')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')

        data = deepcopy(system_data)
        data["configuration"]["qos"] = "/rest/v1/system/qoss/p2"

        response_status, response_data = execute_request(
            system_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'must have the same algorithm on all queues.' in response_data

    def test_system_qos_put_validate_apply_global_profiles_contain_same_queues(self):
        self.s1.cmdCLI('no qos schedule-profile p2')
        self.s1.cmdCLI('qos schedule-profile p2')
        self.s1.cmdCLI('strict queue 5')
        self.s1.cmdCLI('exit')

        data = deepcopy(system_data)
        data["configuration"]["qos"] = "/rest/v1/system/qoss/p2"

        response_status, response_data = execute_request(
            system_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'must contain all of the' in response_data

    def test_system_qos_put_validate_apply_port_profiles_contain_same_queues(self):
        # Create profiles with just one queue.
        self.s1.cmdCLI('no qos queue-profile p2')
        self.s1.cmdCLI('qos queue-profile p2')
        self.s1.cmdCLI('map queue 0 local-priority 0')
        self.s1.cmdCLI('map queue 0 local-priority 1')
        self.s1.cmdCLI('map queue 0 local-priority 2')
        self.s1.cmdCLI('map queue 0 local-priority 3')
        self.s1.cmdCLI('map queue 0 local-priority 4')
        self.s1.cmdCLI('map queue 0 local-priority 5')
        self.s1.cmdCLI('map queue 0 local-priority 6')
        self.s1.cmdCLI('map queue 0 local-priority 7')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('no qos schedule-profile p2')
        self.s1.cmdCLI('qos schedule-profile p2')
        self.s1.cmdCLI('strict queue 0')
        self.s1.cmdCLI('exit')

        # Apply the one-queue profiles to system and port.
        self.s1.cmdCLI('apply qos queue-profile p2 schedule-profile p2')
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('apply qos schedule-profile p2')
        self.s1.cmdCLI('exit')

        # Globally applying the default profiles should fail, since they
        # have 8 queues rather than 1 queue.
        data = deepcopy(system_data)

        response_status, response_data = execute_request(
            system_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'must contain all of the' in response_data
