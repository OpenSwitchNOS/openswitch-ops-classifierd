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

class QosCosMapCliTest(OpsVsiTest):
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

        s1.cmdCLI('no qos cos-map 7')

        return s1

    def qosCosMapCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos cos-map 7 local-priority 1 color red name MyName1')
        s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow name MyName2')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point 7' in out
        assert 'local_priority 2' in out
        assert 'color yellow' in out
        assert 'name MyName2' in out

    def qosCosMapCommandWithIllegalCodePoint(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos cos-map 8 local-priority 2 color yellow name MyName2')
        assert 'Unknown command' in out

    def qosCosMapCommandWithNullCodePoint(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos cos-map local-priority 2 color yellow name MyName2')
        assert 'Unknown command' in out

    def qosCosMapCommandWithIllegalLocalPriority(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos cos-map 7 local-priority 8 color yellow name MyName2')
        assert 'Unknown command' in out

    def qosCosMapCommandWithNullLocalPriority(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos cos-map 7 color yellow name MyName2')
        assert 'Unknown command' in out

    def qosCosMapCommandWithIllegalColor(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos cos-map 7 local-priority 2 color illegal name MyName2')
        assert 'Unknown command' in out

    def qosCosMapCommandWithNullColor(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos cos-map 7 local-priority 2 name MyName2')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point 7' in out
        assert 'local_priority 2' in out
        assert 'color' not in out
        assert 'name MyName2' in out

    def qosCosMapCommandWithIllegalName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow '
                'name NameThatIsLongerThan64Characterssssssssssssssssssssssssssssssssss')
        assert 'allowed' in out

    def qosCosMapCommandWithNullName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point 7' in out
        assert 'local_priority 2' in out
        assert 'color yellow' in out
        assert 'name <empty>' in out

    def qosCosMapNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow name MyName2')
        s1.cmdCLI('no qos cos-map 7')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point' not in out
        assert 'local_priority' not in out
        assert 'color' not in out
        assert 'name' not in out

    def qosCosMapShowCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow name MyName2')
        out = s1.cmdCLI('do show qos cos-map')
        assert '7          2              yellow  MyName2' in out

    def qosCosMapShowCommandWithDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow name MyName2')
        out = s1.cmdCLI('do show qos cos-map default')
        assert '7          7              green   Network_Control' in out

    def qosCosMapShowRunningConfigWithDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('qos cos-map 1 local-priority 0 color green name "Background"')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point' not in out
        assert 'local_priority' not in out
        assert 'color' not in out
        assert 'name' not in out

class Test_qos_cos_map_cli:
    def setup_class(cls):
        Test_qos_cos_map_cli.test = QosCosMapCliTest()

    def teardown_class(cls):
        Test_qos_cos_map_cli.test.net.stop()

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

    def test_qosCosMapCommand(self):
        self.test.qosCosMapCommand()

    def test_qosCosMapCommandWithIllegalCodePoint(self):
        self.test.qosCosMapCommandWithIllegalCodePoint()

    def test_qosCosMapCommandWithNullCodePoint(self):
        self.test.qosCosMapCommandWithNullCodePoint()

    def test_qosCosMapCommandWithIllegalLocalPriority(self):
        self.test.qosCosMapCommandWithIllegalLocalPriority()

    def test_qosCosMapCommandWithNullLocalPriority(self):
        self.test.qosCosMapCommandWithNullLocalPriority()

    def test_qosCosMapCommandWithIllegalColor(self):
        self.test.qosCosMapCommandWithIllegalColor()

    def test_qosCosMapCommandWithNullColor(self):
        self.test.qosCosMapCommandWithNullColor()

    def test_qosCosMapCommandWithIllegalName(self):
        self.test.qosCosMapCommandWithIllegalName()

    def test_qosCosMapCommandWithNullName(self):
        self.test.qosCosMapCommandWithNullName()

    def test_qosCosMapNoCommand(self):
        self.test.qosCosMapNoCommand()

    def test_qosCosMapShowCommand(self):
        self.test.qosCosMapShowCommand()

    def test_qosCosMapShowCommandWithDefault(self):
        self.test.qosCosMapShowCommandWithDefault()

    def test_qosCosMapShowRunningConfigWithDefault(self):
        self.test.qosCosMapShowRunningConfigWithDefault()