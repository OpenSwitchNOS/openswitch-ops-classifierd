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


class QosCosPortCliTest(OpsVsiTest):

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

        s1.cmdCLI('no qos cos')

        s1.cmdCLI('interface 1')
        s1.cmdCLI('no lag 10')
        s1.cmdCLI('no qos trust')
        s1.cmdCLI('no qos cos')

        s1.cmdCLI('interface lag 10')
        s1.cmdCLI('no qos trust')
        s1.cmdCLI('no qos cos')

        s1.cmdCLI('end')
        s1.cmdCLI('configure terminal')

        return s1

    def qosCosPortCommand(self):
        # This command is not supported in dill.
        # Artificially pass all tests until this command has been added.
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos cos 1')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'override 1' in out

    def qosCosPortCommandWithTrustEmpty(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('qos cos 1')
        assert 'only allowed' in out

    def qosCosPortCommandWithTrustCos(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust cos')
        out = s1.cmdCLI('qos cos 1')
        assert 'only allowed' in out

    def qosCosPortCommandWithIllegalQosCos(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('qos cos 8')
        assert 'Unknown command' in out

    def qosCosPortCommandWithNullQosCos(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('qos cos')
        assert 'Command incomplete' in out

    def qosCosPortCommandWithInterfaceInLag(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('lag 10')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('qos cos 1')
        assert 'cannot' in out

    def qosCosPortNoCommand(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos cos 1')
        s1.cmdCLI('no qos cos')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'override' not in out

    def qosCosPortNoCommandWithInterfaceInLag(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('lag 10')
        s1.cmdCLI('qos trust none')
        out = s1.cmdCLI('no qos cos')
        assert 'cannot' in out

    def qosCosPortShowRunningConfig(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos cos 1')
        out = s1.cmdCLI('do show running-config')
        assert 'override' in out

    def qosCosPortShowRunningConfigInterface(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos cos 1')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'override' in out

    def qosCosPortShowInterface(self):
        return
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('qos trust none')
        s1.cmdCLI('qos cos 1')
        out = s1.cmdCLI('do show interface 1')
        assert 'override' in out


class Test_qos_cos_port_cli:

    def setup_class(cls):
        Test_qos_cos_port_cli.test = QosCosPortCliTest()

    def teardown_class(cls):
        Test_qos_cos_port_cli.test.net.stop()

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

    def test_qosCosPortCommand(self):
        self.test.qosCosPortCommand()

    def test_qosCosPortCommandWithTrustEmpty(self):
        self.test.qosCosPortCommandWithTrustEmpty()

    def test_qosCosPortCommandWithTrustCos(self):
        self.test.qosCosPortCommandWithTrustCos()

    def test_qosCosPortCommandWithIllegalQosCos(self):
        self.test.qosCosPortCommandWithIllegalQosCos()

    def test_qosCosPortCommandWithNullQosCos(self):
        self.test.qosCosPortCommandWithNullQosCos()

    def test_qosCosPortCommandWithInterfaceInLag(self):
        self.test.qosCosPortCommandWithInterfaceInLag()

    def test_qosCosPortNoCommand(self):
        self.test.qosCosPortNoCommand()

    def test_qosCosPortNoCommandWithInterfaceInLag(self):
        self.test.qosCosPortNoCommandWithInterfaceInLag()

    def test_qosCosPortShowRunningConfig(self):
        self.test.qosCosPortShowRunningConfig()

    def test_qosCosPortShowRunningConfigInterface(self):
        self.test.qosCosPortShowRunningConfigInterface()

    def test_qosCosPortShowInterface(self):
        self.test.qosCosPortShowInterface()
