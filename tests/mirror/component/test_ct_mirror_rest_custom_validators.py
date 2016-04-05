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

class MirrorRestCustomValidatorsTest(OpsVsiTest):
    def setupNet(self):
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        topo = SingleSwitchTopo(k=0, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(topo, switch=VsiOpenSwitch,
                           host=Host, link=OpsVsiLink,
                           controller=None, build=True)

class Test_mirror_rest_custom_validators:
    def setup_class(cls):
        Test_mirror_rest_custom_validators.test = MirrorRestCustomValidatorsTest()

        s1 = Test_mirror_rest_custom_validators.test.net.switches[0]

        s1.cmdCLI('end')
        s1.cmdCLI('configure terminal')
        s1.cmdCLI('interface 1')
        s1.cmdCLI('interface 2')
        s1.cmdCLI('interface 3')
        s1.cmdCLI('interface 4')
        s1.cmdCLI('interface lag 10')

        switch_ip = get_switch_ip(s1)
        rest_sanity_check(switch_ip)

    def teardown_class(cls):
        Test_mirror_rest_custom_validators.test.net.stop()

    def setup(self):
        self.s1 = Test_mirror_rest_custom_validators.test.net.switches[0]
        self.switch_ip = get_switch_ip(self.s1)

    def teardown(self):
        pass

    def __del__(self):
        del self.test

    def rest_post_succeeds(self, mirror_data):
        response_status, response_data = execute_request(
            get_mirror_url(), "POST",
            json.dumps(mirror_data), self.switch_ip)
        assert response_status == httplib.CREATED
        assert response_data is ''

    def rest_post_fails(self, mirror_data, error_message):
        response_status, response_data = execute_request(
            get_mirror_url(), "POST",
            json.dumps(mirror_data), self.switch_ip)
        assert response_status == httplib.BAD_REQUEST
        assert error_message in response_data

    def rest_patch(self, mirror_name, mirror_data):
        response_status, response_data = execute_request(
            get_mirror_url(mirror_name), "PATCH",
            json.dumps(mirror_data), self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''

    def rest_put_succeeds(self, mirror_name, mirror_data):
        response_status, response_data = execute_request(
            get_mirror_url(mirror_name), "PUT",
            json.dumps(mirror_data), self.switch_ip)
        assert response_status == httplib.OK
        assert response_data is ''

    def rest_put_fails(self, mirror_name, mirror_data, error_message):
        response_status, response_data = execute_request(
            get_mirror_url(mirror_name), "PUT",
            json.dumps(mirror_data), self.switch_ip)
        assert response_status == httplib.BAD_REQUEST
        assert error_message in response_data

    def rest_delete(self, mirror_name):
        response_status, response_data = execute_request(
            get_mirror_url(mirror_name),
            "DELETE", None, self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''

    def rest_get_succeeds(self, mirror_name):
        response_status, response_data = execute_request(
            get_mirror_url(mirror_name), "GET",
            None, self.switch_ip)

        assert response_status == httplib.OK

        return response_data

    def rest_get_fails(self, mirror_name):
        response_status, response_data = execute_request(
            get_mirror_url(mirror_name), "GET",
            None, self.switch_ip)

        assert response_status == httplib.NOT_FOUND

    def test_1_activate_ms_foo_succeeds(self):
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

        self.rest_post_succeeds(mirror_data)

        actual_data = self.rest_get_succeeds(mirror_name)
        assert "\"name\": \"foo\"" in actual_data
        assert "\"select_src_port\": [\"" + get_port_url(2) + "\"]," \
            in actual_data
        assert "\"select_dst_port\": [\"" + get_port_url(2) + "\"]" \
            in actual_data
        assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
        assert "\"active\": true" in actual_data

    def test_2_add_second_source_to_active_ms_foo_succeeds(self):
        mirror_name = "foo"
        mirror_data = [{"op": "add", "path": "/select_src_port/0",
                                  "value": get_port_url(1)}]

        self.rest_patch(mirror_name, mirror_data)

        actual_data = self.rest_get_succeeds(mirror_name)
        assert "\"name\": \"foo\"" in actual_data
        assert "\"select_src_port\": [\"" + get_port_url(1) + "\","
        " \" + get_port_url(2\"]," in actual_data
        assert "\"select_dst_port\": [\"" + get_port_url(2) + "\"]" \
            in actual_data
        assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
        assert "\"active\": true" in actual_data

    def test_3_remove_first_source_from_active_ms_foo_succeeds(self):
        mirror_name = "foo"
        mirror_data = {
            "configuration": {
                "select_src_port": [get_port_url(1)],
                "select_dst_port": []
            }
        }

        # TODO: use patch instead of put.
        self.rest_put_succeeds(mirror_name, mirror_data)

        actual_data = self.rest_get_succeeds(mirror_name)
        assert "\"name\": \"foo\"" in actual_data
        assert "\"select_src_port\": [\"" + get_port_url(1) + "\"]," \
            in actual_data
        assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
        assert "\"active\": true" in actual_data

    def test_4_attempt_another_ms_without_an_output_port_fails(self):
        mirror_name = "bar"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_src_port": [get_port_url(2)],
                "active": True
            }
        }

        self.rest_post_fails(mirror_data, "output port cannot be empty.")

        self.rest_get_fails(mirror_name)

    def test_5_attempt_another_ms_without_any_source_ports_fails(self):
        mirror_name = "bar"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "output_port": get_port_url(4),
                "active": True
            }
        }

        self.rest_post_fails(mirror_data, \
            "select src port and select dst port cannot both be empty")

        self.rest_get_fails(mirror_name)

    def test_6_activate_ms_bar_succeeds(self):
        mirror_name = "bar"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_dst_port": [get_port_url(1)],
                "output_port": get_port_url(4),
                "active": True
            }
        }

        self.rest_post_succeeds(mirror_data)

        actual_data = self.rest_get_succeeds(mirror_name)
        assert "\"name\": \"bar\"" in actual_data
        assert "\"select_dst_port\": [\"" + get_port_url(1) + "\"]" \
            in actual_data
        assert "output_port\": [\"" + get_port_url(4) + "\"]" in actual_data
        assert "\"active\": true" in actual_data

    def test_7_replace_source_1_with_2_in_active_ms_bar_succeeds(self):
        mirror_name = "bar"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_dst_port": [get_port_url(2)],
                "output_port": get_port_url(4),
                "active": True
            }
        }

        self.rest_put_succeeds(mirror_name, mirror_data)

        actual_data = self.rest_get_succeeds(mirror_name)
        assert "\"name\": \"bar\"" in actual_data
        assert "\"select_dst_port\": [\"" + get_port_url(2) + "\"]" \
            in actual_data
        assert "output_port\": [\"" + get_port_url(4) + "\"]" in actual_data
        assert "\"active\": true" in actual_data

    def test_8_attempt_another_ms_using_existing_destination_fails(self):
        mirror_name = "dup"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_src_port": [get_port_url(1)],
                "output_port": get_port_url(3),
                "active": True
            }
        }

        self.rest_post_fails(mirror_data, \
            "output port cannot be an output port of another active mirror")

        self.rest_get_fails(mirror_name)

    def test_9_attempt_another_ms_op_u_e_rx_source_interface_fails(self):
        mirror_name = "dup"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_src_port": [get_port_url(2)],
                "output_port": get_port_url(1),
                "active": True
            }
        }

        self.rest_post_fails(mirror_data, \
            "output port cannot be a select src port of another active mirror")

        self.rest_get_fails(mirror_name)

    def test_10_attempt_another_ms_op_u_e_tx_source_interface_fails(self):
        mirror_name = "dup"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_src_port": [get_port_url(1)],
                "output_port": get_port_url(2),
                "active": True
            }
        }

        self.rest_post_fails(mirror_data, \
            "output port cannot be a select dst port of another active mirror")

        self.rest_get_fails(mirror_name)

    def test_11_attempt_another_ms_rx_source_u_e_op_fails(self):
        mirror_name = "dup"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_src_port": [get_port_url(3)],
                "output_port": get_port_url(4),
                "active": True
            }
        }

        self.rest_post_fails(mirror_data, \
            "cannot be")

        self.rest_get_fails(mirror_name)

    def test_12_attempt_another_ms_tx_source_u_e_op_fails(self):
        mirror_name = "dup"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_dst_port": [get_port_url(3)],
                "output_port": get_port_url(4),
                "active": True
            }
        }

        self.rest_post_fails(mirror_data, \
            "cannot be")

        self.rest_get_fails(mirror_name)

    def test_13_attempt_another_ms_with_same_rx_source_and_op_fails(self):
        mirror_name = "dup"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_src_port": [get_port_url(4)],
                "output_port": get_port_url(4),
                "active": True
            }
        }

        self.rest_post_fails(mirror_data, \
            "output port cannot also be a select src port")

        self.rest_get_fails(mirror_name)

    def test_14_attempt_another_ms_with_same_tx_source_and_op_fails(self):
        mirror_name = "dup"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_dst_port": [get_port_url(4)],
                "output_port": get_port_url(4),
                "active": True
            }
        }

        self.rest_post_fails(mirror_data, \
            "output port cannot also be a select dst port")

        self.rest_get_fails(mirror_name)

    def test_15_create_inactive_duplicate_of_mirror_session_succeeds(self):
        mirror_name = "dup"
        mirror_data = {
            "configuration": {
                "name": mirror_name,
                "select_src_port": [get_port_url(1)],
                "output_port": get_port_url(3)
            }
        }

        self.rest_post_succeeds(mirror_data)

        actual_data = self.rest_get_succeeds(mirror_name)
        assert "\"name\": \"dup\"" in actual_data
        assert "\"select_src_port\": [\"" + get_port_url(1) + "\"]," \
            in actual_data
        assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data

    def test_16_deactivate_mirror_session_foo_succeeds(self):
        mirror_name = "foo"
        mirror_data = {
            "configuration": {
                "active": False
            }
        }

        # TODO: use patch instead of put.
        self.rest_put_succeeds(mirror_name, mirror_data)

        actual_data = self.rest_get_succeeds(mirror_name)
        print actual_data
        assert "\"name\": \"foo\"" in actual_data
        assert "\"select_src_port\": [\"" + get_port_url(1) + "\"]," \
            in actual_data
        assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
        assert "\"active\": false" in actual_data

    def test_17_activate_mirror_session_dup_succeeds(self):
        mirror_name = "dup"
        mirror_data = {
            "configuration": {
                "active": True
            }
        }

        # TODO: use patch instead of put.
        self.rest_put_succeeds(mirror_name, mirror_data)

        actual_data = self.rest_get_succeeds(mirror_name)
        print actual_data
        assert "\"name\": \"dup\"" in actual_data
        assert "\"select_src_port\": [\"" + get_port_url(1) + "\"]," \
            in actual_data
        assert "output_port\": [\"" + get_port_url(3) + "\"]" in actual_data
        assert "\"active\": true" in actual_data

    def test_18_remove_inactivate_mirror_session_foo_succeeds(self):
        mirror_name = "foo"

        self.rest_delete(mirror_name)

        self.rest_get_fails(mirror_name)

    def test_19_remove_activate_mirror_session_dup_succeeds(self):
        mirror_name = "dup"

        self.rest_delete(mirror_name)

        self.rest_get_fails(mirror_name)

    def test_20_remove_activate_mirror_session_bar_succeeds(self):
        mirror_name = "bar"

        self.rest_delete(mirror_name)

        self.rest_get_fails(mirror_name)

    def test_add_active_mirror_foo_non_system_interface_fails(self):
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

        self.rest_post_fails(mirror_data, \
            "mirror can only contain interfaces of type system")

        self.rest_get_fails(mirror_name)

    def test_add_active_mirror_foo_empty_lag_fails(self):
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

        self.rest_post_fails(mirror_data, \
            "must contain at least one interface")

        self.rest_get_fails(mirror_name)
