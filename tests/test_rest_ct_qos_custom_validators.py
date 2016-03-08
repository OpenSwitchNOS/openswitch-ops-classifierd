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
        "qos_config": {
            "qos_trust": "none",
            "dscp_override": "1"
        }
    }
}

qos_cos_map_entry_url = "/rest/v1/system/qos_cos_map_entries/1"

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

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('interface 1')

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def teardown(self):
        pass

    def __del__(self):
        del self.test

    def test_qosCosMapEntryValidateDeleteNotAllowed(self):
        response_status, response_data = execute_request(
            qos_cos_map_entry_url, "DELETE",
            None, self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'cannot' in response_data

    def test_port_qos(self):
        data = deepcopy(port_data)

        response_status, response_data = execute_request(
            port_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.OK
        assert response_data is ''

    def test_port_qos_validate_port_override_has_port_trust_mode_none(self):
        data = deepcopy(port_data)
        data["configuration"]["qos_config"]["qos_trust"] = "dscp"

        response_status, response_data = execute_request(
            port_url, "PUT",
            json.dumps(data), self.switch_ip)

        assert response_status == httplib.BAD_REQUEST
        assert 'only allowed' in response_data
