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

class QosDscpMapCliTest(OpsVsiTest):
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

        s1.cmdCLI('no qos dscp-map 38')

        return s1

    def qosDscpMapCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos dscp-map 38 local-priority 1 cos 2 color green name MyName1')
        s1.cmdCLI('qos dscp-map 38 local-priority 2 cos 3 color yellow name MyName2')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point 38' in out
        assert 'local_priority 2' in out
        assert 'cos 3' in out
        assert 'color yellow' in out
        assert 'name \"MyName2\"' in out

    def qosDscpMapCommandWithIllegalCodePoint(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map 64 local-priority 2 cos 3 color yellow name MyName2')
        assert 'Unknown command' in out

    def qosDscpMapCommandWithNullCodePoint(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map local-priority 2 cos 3 color yellow name MyName2')
        assert 'Unknown command' in out

    def qosDscpMapCommandWithIllegalLocalPriority(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map 38 local-priority 8 cos 3 color yellow name MyName2')
        assert 'Unknown command' in out

    def qosDscpMapCommandWithNullLocalPriority(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map 38 cos 3 color yellow name MyName2')
        assert 'Unknown command' in out

    def qosDscpMapCommandWithIllegalCos(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map 38 local-priority 2 cos 8 color yellow name MyName2')
        assert 'Unknown command' in out

    def qosDscpMapCommandWithNullCos(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map 38 local-priority 2 color yellow name MyName2')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point 38' in out
        assert 'local_priority 2' in out
        assert 'cos <empty>' in out
        assert 'color yellow' in out
        assert 'name \"MyName2\"' in out

    def qosDscpMapCommandWithIllegalColor(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map 38 local-priority 2 cos 3 color illegal name MyName2')
        assert 'Unknown command' in out

    def qosDscpMapCommandWithNullColor(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map 38 local-priority 2 cos 3 name MyName2')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point 38' in out
        assert 'local_priority 2' in out
        assert 'cos 3' in out
        assert 'color green' in out
        assert 'name \"MyName2\"' in out

    def qosDscpMapCommandWithIllegalName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map 38 local-priority 2 cos 3 color yellow '
                'name NameThatIsLongerThan64Characterssssssssssssssssssssssssssssssssss')
        assert 'allowed' in out

    def qosDscpMapCommandWithNullName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos dscp-map 38 local-priority 2 cos 3 color yellow')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point 38' in out
        assert 'local_priority 2' in out
        assert 'cos 3' in out
        assert 'color yellow' in out
        assert 'name <empty>' in out

    def qosDscpMapNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos dscp-map 38 local-priority 2 cos 3 color yellow name MyName2')
        s1.cmdCLI('no qos dscp-map 38')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point' not in out
        assert 'local_priority' not in out
        assert 'cos' not in out
        assert 'color' not in out
        assert 'name' not in out

    def qosDscpMapShowCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos dscp-map 38 local-priority 2 cos 3 color yellow name MyName2')
        out = s1.cmdCLI('do show qos dscp-map')
        assert '38         2              3   yellow  "MyName2"' in out

    def qosDscpMapShowCommandWithDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('qos dscp-map 38 local-priority 2 cos 3 color yellow name MyName2')
        out = s1.cmdCLI('do show qos dscp-map default')
        assert '38         4              4   red     "AF43"' in out

    def qosDscpMapShowRunningConfigWithDefault(self):
        s1 = self.setUp()
        s1.cmdCLI('qos dscp-map 38 local-priority 4 cos 4 color red name AF43')
        out = s1.cmdCLI('do show running-config')
        assert 'code_point' not in out
        assert 'local_priority' not in out
        assert 'cos' not in out
        assert 'color' not in out
        assert 'name' not in out

class Test_qos_dscp_map_cli:
    def setup_class(cls):
        Test_qos_dscp_map_cli.test = QosDscpMapCliTest()

    def teardown_class(cls):
        Test_qos_dscp_map_cli.test.net.stop()

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

    def test_qosDscpMapCommand(self):
        self.test.qosDscpMapCommand()

    def test_qosDscpMapCommandWithIllegalCodePoint(self):
        self.test.qosDscpMapCommandWithIllegalCodePoint()

    def test_qosDscpMapCommandWithNullCodePoint(self):
        self.test.qosDscpMapCommandWithNullCodePoint()

    def test_qosDscpMapCommandWithIllegalLocalPriority(self):
        self.test.qosDscpMapCommandWithIllegalLocalPriority()

    def test_qosDscpMapCommandWithNullLocalPriority(self):
        self.test.qosDscpMapCommandWithNullLocalPriority()

    def test_qosDscpMapCommandWithIllegalCos(self):
        self.test.qosDscpMapCommandWithIllegalCos()

    def test_qosDscpMapCommandWithNullCos(self):
        self.test.qosDscpMapCommandWithNullCos()

    def test_qosDscpMapCommandWithIllegalColor(self):
        self.test.qosDscpMapCommandWithIllegalColor()

    def test_qosDscpMapCommandWithNullColor(self):
        self.test.qosDscpMapCommandWithNullColor()

    def test_qosDscpMapCommandWithIllegalName(self):
        self.test.qosDscpMapCommandWithIllegalName()

    def test_qosDscpMapCommandWithNullName(self):
        self.test.qosDscpMapCommandWithNullName()

    def test_qosDscpMapNoCommand(self):
        self.test.qosDscpMapNoCommand()

    def test_qosDscpMapShowCommand(self):
        self.test.qosDscpMapShowCommand()

    def test_qosDscpMapShowCommandWithDefault(self):
        self.test.qosDscpMapShowCommandWithDefault()

    def test_qosDscpMapShowRunningConfigWithDefault(self):
        self.test.qosDscpMapShowRunningConfigWithDefault()