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

class QosDscpPortCliTest(OpsVsiTest):
    def setupNet(self):
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        topo = SingleSwitchTopo(k=0, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(topo, switch=VsiOpenSwitch,
                           host=Host, link=OpsVsiLink,
                           controller=None, build=True)

    def setUp(self):
        s1 = self.net.switches[0]

        s1.cmdCLI('end')
        s1.cmdCLI('configure terminal')

        s1.cmdCLI('no qos dscp')

        s1.cmdCLI('interface 1')
        s1.cmdCLI('no lag 10')
        s1.cmdCLI('no qos trust')
        s1.cmdCLI('no qos dscp')

        s1.cmdCLI('interface lag 10')
        s1.cmdCLI('no qos trust')
        s1.cmdCLI('no qos dscp')

        s1.cmdCLI('end')
        s1.cmdCLI('configure terminal')

        return s1

    def qosDscpPortCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos dscp 1')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'override 1' in out

    def qosDscpPortCommandWithTrustEmpty(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('qos dscp 1')
        assert 'only allowed' in out

    def qosDscpPortCommandWithTrustDscp(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust dscp')
        out = s1.cmdCLI('qos dscp 1')
        assert 'only allowed' in out

    def qosDscpPortCommandWithIllegalQosDscp(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('qos dscp 64')
        assert 'Unknown command' in out

    def qosDscpPortCommandWithNullQosDscp(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('qos dscp')
        assert 'Command incomplete' in out

    def qosDscpPortCommandWithInterfaceInLag(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('lag 10')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('qos dscp 1')
        assert 'cannot' in out

    def qosDscpPortNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos dscp 1')
        s1.cmdCLI('no qos dscp')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'override' not in out

    def qosDscpPortNoCommandWithInterfaceInLag(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('lag 10')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('no qos dscp')
        assert 'cannot' in out

    def qosDscpPortShowRunningConfig(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos dscp 1')
        out = s1.cmdCLI('do show running-config')
        assert 'override' in out

    def qosDscpPortShowRunningConfigInterface(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos dscp 1')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'override' in out

    def qosDscpPortShowInterface(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos dscp 1')
        out = s1.cmdCLI('do show interface 1')
        assert 'override' in out

class Test_qos_dscp_port_cli:
    def setup_class(cls):
        Test_qos_dscp_port_cli.test = QosDscpPortCliTest()

    def teardown_class(cls):
        Test_qos_dscp_port_cli.test.net.stop()

    def setup(self):
        pass

    def teardown(self):
        pass

    def setup_method(self, method):
        pass

    def teardown_method(self, method):
        pass

    def __del__(self):
        del self.test

    def test_qosDscpPortCommand(self):
        self.test.qosDscpPortCommand()
    def test_qosDscpPortCommandWithTrustEmpty(self):
        self.test.qosDscpPortCommandWithTrustEmpty()
    def test_qosDscpPortCommandWithTrustDscp(self):
        self.test.qosDscpPortCommandWithTrustDscp()
    def test_qosDscpPortCommandWithIllegalQosDscp(self):
        self.test.qosDscpPortCommandWithIllegalQosDscp()
    def test_qosDscpPortCommandWithNullQosDscp(self):
        self.test.qosDscpPortCommandWithNullQosDscp()
    def test_qosDscpPortCommandWithInterfaceInLag(self):
        self.test.qosDscpPortCommandWithInterfaceInLag()
    def test_qosDscpPortNoCommand(self):
        self.test.qosDscpPortNoCommand()
    def test_qosDscpPortNoCommandWithInterfaceInLag(self):
        self.test.qosDscpPortNoCommandWithInterfaceInLag()
    def test_qosDscpPortShowRunningConfig(self):
        self.test.qosDscpPortShowRunningConfig()
    def test_qosDscpPortShowRunningConfigInterface(self):
        self.test.qosDscpPortShowRunningConfigInterface()
    def test_qosDscpPortShowInterface(self):
        self.test.qosDscpPortShowInterface()