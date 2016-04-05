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
        s1.cmdCLI('interface 10')
        s1.cmdCLI('interface 11')
        s1.cmdCLI('interface 12')
        s1.cmdCLI('interface 20')
        s1.cmdCLI('interface 21')
        s1.cmdCLI('interface 22')

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

    def test_active_mirror_with_different_ports(self):
        existing_mirror_data = create_existing_mirror_data()

        new_mirror_data = create_new_mirror_data()

        new_mirror_patch_data = [{"op": "add", "path": "/output_port",
                                  "value": get_port_url(1)}]

        existing_mirror_name = existing_mirror_data["configuration"]["name"]
        new_mirror_name = new_mirror_data["configuration"]["name"]

        # Set up.
        response_status, response_data = execute_request(
            get_mirror_url(), "POST",
            json.dumps(existing_mirror_data), self.switch_ip)
        assert response_status == httplib.CREATED
        assert response_data is ''

        # Test post.
        response_status, response_data = execute_request(
            get_mirror_url(), "POST",
            json.dumps(new_mirror_data), self.switch_ip)
        assert response_status == httplib.CREATED
        assert response_data is ''

        # Test put.
        response_status, response_data = execute_request(
            get_mirror_url(new_mirror_name), "PUT",
            json.dumps(new_mirror_data), self.switch_ip)
        assert response_status == httplib.OK
        assert response_data is ''

        # Test patch.
        response_status, response_data = execute_request(
            get_mirror_url(new_mirror_name), "PATCH",
            json.dumps(new_mirror_patch_data), self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''

        # Tear down.
        response_status, response_data = execute_request(
            get_mirror_url(new_mirror_name),
            "DELETE", None, self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''
        response_status, response_data = execute_request(
            get_mirror_url(existing_mirror_name),
            "DELETE", None, self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''

    def test_inactive_mirror_with_same_ports(self):
        existing_mirror_data = create_existing_mirror_data()
        existing_mirror_data["configuration"]["active"] = True
        existing_mirror_data["configuration"]["output_port"] = \
            get_port_url(10)
        existing_mirror_data["configuration"]["select_src_port"] = \
            [get_port_url(11)]
        existing_mirror_data["configuration"]["select_dst_port"] = \
            [get_port_url(12)]

        new_mirror_data = create_new_mirror_data()
        new_mirror_data["configuration"]["active"] = False
        new_mirror_data["configuration"]["output_port"] = \
            get_port_url(10)
        new_mirror_data["configuration"]["select_src_port"] = \
            [get_port_url(11)]
        new_mirror_data["configuration"]["select_dst_port"] = \
            [get_port_url(12)]

        new_mirror_patch_data = \
            [{"op": "add", "path": "/active", "value": False}, \
            {"op": "add", "path": "/output_port", \
                "value": get_port_url(10)}, \
            {"op": "add", "path": "/select_src_port", \
                "value": [get_port_url(11)]}, \
            {"op": "add", "path": "/select_dst_port", \
                "value": [get_port_url(12)]}]

        existing_mirror_name = existing_mirror_data["configuration"]["name"]
        new_mirror_name = new_mirror_data["configuration"]["name"]

        # Set up.
        response_status, response_data = execute_request(
            get_mirror_url(), "POST",
            json.dumps(existing_mirror_data), self.switch_ip)
        assert response_status == httplib.CREATED
        assert response_data is ''

        # Test post.
        response_status, response_data = execute_request(
            get_mirror_url(), "POST",
            json.dumps(new_mirror_data), self.switch_ip)
        assert response_status == httplib.CREATED
        assert response_data is ''

        # Test put.
        response_status, response_data = execute_request(
            get_mirror_url(new_mirror_name), "PUT",
            json.dumps(new_mirror_data), self.switch_ip)
        assert response_status == httplib.OK
        assert response_data is ''

        # Test patch.
        response_status, response_data = execute_request(
            get_mirror_url(new_mirror_name), "PATCH",
            json.dumps(new_mirror_patch_data), self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''

        # Tear down.
        response_status, response_data = execute_request(
            get_mirror_url(new_mirror_name),
            "DELETE", None, self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''
        response_status, response_data = execute_request(
            get_mirror_url(existing_mirror_name),
            "DELETE", None, self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''

    def helper_mirror_validate(self, existing_mirror_data, new_mirror_data,
                               new_mirror_patch_data,
                               expected_status, expected_data):
        existing_mirror_name = existing_mirror_data["configuration"]["name"]
        new_mirror_name = new_mirror_data["configuration"]["name"]

        # Set up.
        response_status, response_data = execute_request(
            get_mirror_url(), "POST",
            json.dumps(existing_mirror_data), self.switch_ip)
        assert response_status == httplib.CREATED
        assert response_data is ''

        # Post an inactive version of the new mirror.
        inactive_new_mirror_data = deepcopy(new_mirror_data)
        inactive_new_mirror_data["configuration"]["active"] = False
        response_status, response_data = execute_request(
            get_mirror_url(), "POST",
            json.dumps(inactive_new_mirror_data), self.switch_ip)
        assert response_status == httplib.CREATED
        assert response_data is ''

        # Test post.
        post_new_mirror_data = deepcopy(new_mirror_data)
        post_new_mirror_data["configuration"]["name"] = "post_new_mirror"
        response_status, response_data = execute_request(
            get_mirror_url(), "POST",
            json.dumps(post_new_mirror_data), self.switch_ip)
        assert expected_status == response_status
        assert expected_data in response_data

        # Test put.
        response_status, response_data = execute_request(
            get_mirror_url(new_mirror_name), "PUT",
            json.dumps(new_mirror_data), self.switch_ip)
        assert expected_status == response_status
        assert expected_data in response_data

        # Test patch.
        response_status, response_data = execute_request(
            get_mirror_url(new_mirror_name), "PATCH",
            json.dumps(new_mirror_patch_data), self.switch_ip)
        # Once custom validators support PATCH (taiga 661), enable these.
#         assert expected_status == response_status
#         assert expected_data in response_data

        # Tear down.
        response_status, response_data = execute_request(
            get_mirror_url(new_mirror_name),
            "DELETE", None, self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''
        response_status, response_data = execute_request(
            get_mirror_url(existing_mirror_name),
            "DELETE", None, self.switch_ip)
        assert response_status == httplib.NO_CONTENT
        assert response_data is ''

    def test_mirror_validate_output_port_is_not_existing_select_src_port(self):
        port = get_port_url(1)

        existing_mirror_data = create_existing_mirror_data()
        existing_mirror_data["configuration"]["select_src_port"] = [port]

        new_mirror_data = create_new_mirror_data()
        new_mirror_data["configuration"]["output_port"] = port

        new_mirror_patch_data = [{"op": "add", "path": "/output_port",
                                  "value": port}]

        expected_status = httplib.BAD_REQUEST
        expected_data = 'output port cannot be a select src port'

        self.helper_mirror_validate(existing_mirror_data, new_mirror_data,
                                    new_mirror_patch_data,
                                    expected_status, expected_data)

    def test_mirror_validate_output_port_is_not_existing_select_dst_port(self):
        port = get_port_url(1)

        existing_mirror_data = create_existing_mirror_data()
        existing_mirror_data["configuration"]["select_dst_port"] = [port]

        new_mirror_data = create_new_mirror_data()
        new_mirror_data["configuration"]["output_port"] = port

        new_mirror_patch_data = [{"op": "add", "path": "/output_port",
                                  "value": port}]

        expected_status = httplib.BAD_REQUEST
        expected_data = 'output port cannot be a select dst port'

        self.helper_mirror_validate(existing_mirror_data, new_mirror_data,
                                    new_mirror_patch_data,
                                    expected_status, expected_data)

    def test_mirror_validate_output_port_is_not_existing_output_port(self):
        port = get_port_url(1)

        existing_mirror_data = create_existing_mirror_data()
        existing_mirror_data["configuration"]["output_port"] = port

        new_mirror_data = create_new_mirror_data()
        new_mirror_data["configuration"]["output_port"] = port

        new_mirror_patch_data = [{"op": "add", "path": "/output_port",
                                  "value": port}]

        expected_status = httplib.BAD_REQUEST
        expected_data = 'output port cannot be an output port'

        self.helper_mirror_validate(existing_mirror_data, new_mirror_data,
                                    new_mirror_patch_data,
                                    expected_status, expected_data)

    def test_mirror_validate_select_src_prt_is_not_existing_output_port(self):
        port = get_port_url(1)

        existing_mirror_data = create_existing_mirror_data()
        existing_mirror_data["configuration"]["output_port"] = port

        new_mirror_data = create_new_mirror_data()
        new_mirror_data["configuration"]["select_src_port"] = [port]

        new_mirror_patch_data = [{"op": "add", "path": "/select_src_port",
                                  "value": [port]}]

        expected_status = httplib.BAD_REQUEST
        expected_data = 'select src port cannot be an output port'

        self.helper_mirror_validate(existing_mirror_data, new_mirror_data,
                                    new_mirror_patch_data,
                                    expected_status, expected_data)

    def test_mirror_validate_select_dst_prt_is_not_existing_output_port(self):
        port = get_port_url(1)

        existing_mirror_data = create_existing_mirror_data()
        existing_mirror_data["configuration"]["output_port"] = port

        new_mirror_data = create_new_mirror_data()
        new_mirror_data["configuration"]["select_dst_port"] = [port]

        new_mirror_patch_data = [{"op": "add", "path": "/select_dst_port",
                                  "value": [port]}]

        expected_status = httplib.BAD_REQUEST
        expected_data = 'select dst port cannot be an output port'

        self.helper_mirror_validate(existing_mirror_data, new_mirror_data,
                                    new_mirror_patch_data,
                                    expected_status, expected_data)

    def test_mirror_validate_output_port_is_not_empty(self):
        existing_mirror_data = create_existing_mirror_data()

        new_mirror_data = create_new_mirror_data()
        del new_mirror_data["configuration"]["output_port"]

        new_mirror_patch_data = [{ "op": "remove", "path": "/output_port" }]

        expected_status = httplib.BAD_REQUEST
        expected_data = 'output port cannot be empty'

        self.helper_mirror_validate(existing_mirror_data, new_mirror_data,
                                    new_mirror_patch_data,
                                    expected_status, expected_data)

    def test_mirror_validate_selects_are_not_empty(self):
        existing_mirror_data = create_existing_mirror_data()

        new_mirror_data = create_new_mirror_data()
        del new_mirror_data["configuration"]["select_src_port"]
        del new_mirror_data["configuration"]["select_dst_port"]

        new_mirror_patch_data = \
            [{ "op": "remove", "path": "/select_src_port" }, \
            { "op": "remove", "path": "/select_dst_port" }]

        expected_status = httplib.BAD_REQUEST
        expected_data = 'select src port and select dst port cannot ' \
            'both be empty'

        self.helper_mirror_validate(existing_mirror_data, new_mirror_data,
                                    new_mirror_patch_data,
                                    expected_status, expected_data)

    def test_mirror_validate_output_port_is_not_this_select_src_port(self):
        port = get_port_url(1)

        existing_mirror_data = create_existing_mirror_data()

        new_mirror_data = create_new_mirror_data()
        new_mirror_data["configuration"]["output_port"] = port
        new_mirror_data["configuration"]["select_src_port"] = [port]

        new_mirror_patch_data = \
            [{"op": "add", "path": "/output_port", "value": port}, \
             {"op": "add", "path": "/select_src_port", "value": [port]}]

        expected_status = httplib.BAD_REQUEST
        expected_data = 'output port cannot also be a select src port'

        self.helper_mirror_validate(existing_mirror_data, new_mirror_data,
                                    new_mirror_patch_data,
                                    expected_status, expected_data)

    def test_mirror_validate_output_port_is_not_this_select_dst_port(self):
        port = get_port_url(1)

        existing_mirror_data = create_existing_mirror_data()

        new_mirror_data = create_new_mirror_data()
        new_mirror_data["configuration"]["output_port"] = port
        new_mirror_data["configuration"]["select_dst_port"] = [port]

        new_mirror_patch_data = \
            [{"op": "add", "path": "/output_port", "value": port}, \
             {"op": "add", "path": "/select_dst_port", "value": [port]}]

        expected_status = httplib.BAD_REQUEST
        expected_data = 'output port cannot also be a select dst port'

        self.helper_mirror_validate(existing_mirror_data, new_mirror_data,
                                    new_mirror_patch_data,
                                    expected_status, expected_data)
