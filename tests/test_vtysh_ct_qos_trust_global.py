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

class QosTrustGlobalCliTest(OpsVsiTest):
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

        return s1

    def qosTrustGlobalCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos trust dscp')
        s1.cmdCLI('qos trust cos')
        out = s1.cmdCLI('do show running-config')
        assert 'qos trust cos' in out

    def qosTrustGlobalCommandWithIllegalQosTrust(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos trust illegal')
        assert 'Unknown command' in out

    def qosTrustGlobalCommandWithNullQosTrust(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos trust')
        assert 'Command incomplete' in out

    def qosTrustGlobalNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos trust dscp')
        s1.cmdCLI('no qos trust')
        out = s1.cmdCLI('do show running-config')
        assert 'qos trust' not in out

    def qosTrustGlobalShowCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos trust dscp')
        out = s1.cmdCLI('do show qos trust')
        assert 'qos trust dscp' in out

    def qosTrustGlobalShowCommandWithDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('qos trust dscp')
        out = s1.cmdCLI('do show qos trust default')
        assert 'qos trust none' in out

    def qosTrustGlobalShowRunningConfigWithDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('do show running-config')
        assert 'qos trust' not in out

class Test_qos_trust_global_cli:
    def setup_class(cls):
        Test_qos_trust_global_cli.test = QosTrustGlobalCliTest()

    def teardown_class(cls):
        Test_qos_trust_global_cli.test.net.stop()

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

    def test_qosTrustGlobalCommand(self):
        self.test.qosTrustGlobalCommand()

    def test_qosTrustGlobalCommandWithIllegalQosTrust(self):
        self.test.qosTrustGlobalCommandWithIllegalQosTrust()

    def test_qosTrustGlobalCommandWithNullQosTrust(self):
        self.test.qosTrustGlobalCommandWithNullQosTrust()

    def test_qosTrustGlobalNoCommand(self):
        self.test.qosTrustGlobalNoCommand()

    def test_qosTrustGlobalShowCommand(self):
        self.test.qosTrustGlobalShowCommand()

    def test_qosTrustGlobalShowCommandWithDefault(self):
        self.test.qosTrustGlobalShowCommandWithDefault()

    def test_qosTrustGlobalShowRunningConfigWithDefault(self):
        self.test.qosTrustGlobalShowRunningConfigWithDefault()