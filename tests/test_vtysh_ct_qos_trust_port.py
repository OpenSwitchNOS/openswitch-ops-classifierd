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

class QosTrustPortCliTest(OpsVsiTest):
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

        s1.cmdCLI('no qos trust')

        s1.cmdCLI('interface 1')
        s1.cmdCLI('no lag 10')
        s1.cmdCLI('no qos trust')

        s1.cmdCLI('interface lag 10')
        s1.cmdCLI('no qos trust')

        s1.cmdCLI('end')
        s1.cmdCLI('configure terminal')

        return s1

    def qosTrustPortCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust dscp')
        s1.cmdCLI('qos trust cos')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'qos trust cos' in out

    def qosTrustPortCommandWithIllegalQosTrust(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('qos trust illegal')
        assert 'Unknown command' in out

    def qosTrustPortCommandWithNullQosTrust(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('qos trust')
        assert 'Command incomplete' in out

    def qosTrustPortCommandWithInterfaceInLag(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('lag 10')
        out = s1.cmdCLI('qos trust cos')
        assert 'QoS Trust cannot be configured on a member of a LAG' in out

    def qosTrustPortNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust dscp')
        s1.cmdCLI('no qos trust')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'qos trust' not in out

    def qosTrustPortNoCommandWithInterfaceInLag(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('lag 10')
        out = s1.cmdCLI('no qos trust')
        assert 'QoS Trust cannot be configured on a member of a LAG' in out

    def qosTrustPortShowRunningConfigWithDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('do show running-config')
        assert 'qos trust' in out

    def qosTrustPortShowRunningConfigWithNonDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust dscp')
        out = s1.cmdCLI('do show running-config')
        assert 'qos trust dscp' in out

    def qosTrustPortShowRunningConfigInterfaceWithDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'qos trust' in out

    def qosTrustPortShowRunningConfigInterfaceWithNonDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust dscp')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'qos trust dscp' in out

    def qosTrustPortShowInterfaceWithDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('do show interface 1')
        assert 'qos trust none' in out

    def qosTrustPortShowInterfaceWithNonDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust dscp')
        out = s1.cmdCLI('do show interface 1')
        assert 'qos trust dscp' in out

class Test_qos_trust_port_cli:
    def setup_class(cls):
        Test_qos_trust_port_cli.test = QosTrustPortCliTest()

    def teardown_class(cls):
        Test_qos_trust_port_cli.test.net.stop()

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

    def test_qosTrustPortCommand(self):
        self.test.qosTrustPortCommand()

    def test_qosTrustPortCommandWithIllegalQosTrust(self):
        self.test.qosTrustPortCommandWithIllegalQosTrust()

    def test_qosTrustPortCommandWithNullQosTrust(self):
        self.test.qosTrustPortCommandWithNullQosTrust()

    def test_qosTrustPortCommandWithInterfaceInLag(self):
        self.test.qosTrustPortCommandWithInterfaceInLag()

    def test_qosTrustPortNoCommand(self):
        self.test.qosTrustPortNoCommand()

    def test_qosTrustPortNoCommandWithInterfaceInLag(self):
        self.test.qosTrustPortNoCommandWithInterfaceInLag()

    def test_qosTrustPortShowRunningConfigWithDefault(self):
        self.test.qosTrustPortShowRunningConfigWithDefault()

    def test_qosTrustPortShowRunningConfigWithNonDefault(self):
        self.test.qosTrustPortShowRunningConfigWithNonDefault()

    def test_qosTrustPortShowRunningConfigInterfaceWithDefault(self):
        self.test.qosTrustPortShowRunningConfigInterfaceWithDefault()

    def test_qosTrustPortShowRunningConfigInterfaceWithNonDefault(self):
        self.test.qosTrustPortShowRunningConfigInterfaceWithNonDefault()

    def test_qosTrustPortShowInterfaceWithDefault(self):
        self.test.qosTrustPortShowInterfaceWithDefault()

    def test_qosTrustPortShowInterfaceWithNonDefault(self):
        self.test.qosTrustPortShowInterfaceWithNonDefault()