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

class QosScheduleProfileCliTest(OpsVsiTest):
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

        s1.cmdCLI('no qos schedule-profile p1')

        return s1

    def qosScheduleProfileCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('do show qos schedule-profile')
        assert 'p1' in out

    def qosScheduleProfileCommandWithIllegalName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos schedule-profile p^%$#1')
        assert 'allowed' in out

    def qosScheduleProfileCommandWithNullName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos schedule-profile')
        assert 'incomplete' in out

    def qosScheduleProfileCommandWithStrictName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos schedule-profile strict')
        assert 'cannot' in out

    def qosScheduleProfileCommandWithAppliedProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos schedule-profile default')
        assert 'cannot' in out

    def qosScheduleProfileNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('no qos schedule-profile p1')
        out = s1.cmdCLI('do show qos schedule-profile')
        assert 'p1' not in out

    def qosScheduleProfileNoCommandWithIllegalName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos schedule-profile p^%$#1')
        assert 'allowed' in out

    def qosScheduleProfileNoCommandWithNullName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos schedule-profile')
        assert 'incomplete' in out

    def qosScheduleProfileNoCommandWithStrictName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos schedule-profile strict')
        assert 'cannot' in out

    def qosScheduleProfileNoCommandWithAppliedProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos schedule-profile default')
        assert 'cannot' in out

    def qosScheduleProfileNoCommandWithNonExistentProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos schedule-profile NonExistent')
        assert 'does not exist' in out

    def qosScheduleProfileStrictCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('strict queue 1')
        out = s1.cmdCLI('do show qos schedule-profile p1')
        assert 'strict' in out
        assert '1' in out

    def qosScheduleProfileStrictCommandWithIllegalQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('strict queue 8')
        assert 'Unknown command' in out

    def qosScheduleProfileStrictCommandWithNullQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('strict queue')
        assert 'incomplete' in out

    def qosScheduleProfileStrictNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('strict queue 1')
        s1.cmdCLI('no strict queue 1')
        out = s1.cmdCLI('do show qos schedule-profile p1')
        assert 'strict' not in out

    def qosScheduleProfileStrictNoCommandWithIllegalQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('no strict queue 8')
        assert 'Unknown command' in out

    def qosScheduleProfileStrictNoCommandWithNullQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('no strict queue')
        assert 'incomplete' in out

    def qosScheduleProfileStrictNoCommandWithMissingQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('no strict queue 2')
        assert 'does not have queue_num' in out

    def qosScheduleProfileWrrCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('wrr queue 1 weight 2')
        out = s1.cmdCLI('do show qos schedule-profile p1')
        assert '1' in out
        assert 'weight' in out
        assert '2' in out

    def qosScheduleProfileWrrCommandWithIllegalQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('wrr queue 8 weight 2')
        assert 'Unknown command' in out

    def qosScheduleProfileWrrCommandWithNullQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('wrr queue weight 2')
        assert 'Unknown command' in out

    def qosScheduleProfileWrrCommandWithIllegalWeight(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('wrr queue 1 weight 1024')
        assert 'Unknown command' in out

    def qosScheduleProfileWrrCommandWithNullWeight(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('wrr queue 1 weight')
        assert 'incomplete' in out

    def qosScheduleProfileWrrNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('wrr queue 1 weight 2')
        s1.cmdCLI('no wrr queue 1')
        out = s1.cmdCLI('do show qos schedule-profile p1')
        assert '1         wrr' not in out

    def qosScheduleProfileWrrNoCommandWithIllegalQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('no wrr queue 8 weight 2')
        assert 'Unknown command' in out

    def qosScheduleProfileWrrNoCommandWithNullQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('no wrr queue weight 2')
        assert 'Unknown command' in out

    def qosScheduleProfileWrrNoCommandWithIllegalWeight(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('no wrr queue 1 weight 1024')
        assert 'Unknown command' in out

    def qosScheduleProfileWrrNoCommandWithNullWeight(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('no wrr queue 1 weight')
        assert 'incomplete' in out

    def qosScheduleProfileWrrNoCommandWithMissingQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        out = s1.cmdCLI('no wrr queue 2')
        assert 'does not have queue_num' in out

    def qosScheduleProfileShowCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('strict queue 1')
        out = s1.cmdCLI('do show qos schedule-profile p1')
        assert 'strict' in out
        assert '1' in out

    def qosScheduleProfileShowCommandWithIllegalName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show qos schedule-profile p^%$#1')
        assert 'allowed' in out

    def qosScheduleProfileShowCommandShowsAllProfiles(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show qos schedule-profile')
        assert 'applied' in out
        assert 'default' in out

    def qosScheduleProfileShowCommandFactoryDefault(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show qos schedule-profile factory-default')
        assert 'queue_num' in out

    def qosScheduleProfileShowCommandWithNonExistentProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show qos schedule-profile NonExistent')
        assert 'does not exist' in out

class Test_qos_schedule_profile_cli:
    def setup_class(cls):
        Test_qos_schedule_profile_cli.test = QosScheduleProfileCliTest()

    def teardown_class(cls):
        Test_qos_schedule_profile_cli.test.net.stop()

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

    def test_qosScheduleProfileCommand(self):
        self.test.qosScheduleProfileCommand()
    def test_qosScheduleProfileCommandWithIllegalName(self):
        self.test.qosScheduleProfileCommandWithIllegalName()
    def test_qosScheduleProfileCommandWithNullName(self):
        self.test.qosScheduleProfileCommandWithNullName()
    def test_qosScheduleProfileCommandWithStrictName(self):
        self.test.qosScheduleProfileCommandWithStrictName()
    def test_qosScheduleProfileCommandWithAppliedProfile(self):
        self.test.qosScheduleProfileCommandWithAppliedProfile()
    def test_qosScheduleProfileNoCommand(self):
        self.test.qosScheduleProfileNoCommand()
    def test_qosScheduleProfileNoCommandWithIllegalName(self):
        self.test.qosScheduleProfileNoCommandWithIllegalName()
    def test_qosScheduleProfileNoCommandWithNullName(self):
        self.test.qosScheduleProfileNoCommandWithNullName()
    def test_qosScheduleProfileNoCommandWithStrictName(self):
        self.test.qosScheduleProfileNoCommandWithStrictName()
    def test_qosScheduleProfileNoCommandWithAppliedProfile(self):
        self.test.qosScheduleProfileNoCommandWithAppliedProfile()
    def test_qosScheduleProfileNoCommandWithNonExistentProfile(self):
        self.test.qosScheduleProfileNoCommandWithNonExistentProfile()
    def test_qosScheduleProfileStrictCommand(self):
        self.test.qosScheduleProfileStrictCommand()
    def test_qosScheduleProfileStrictCommandWithIllegalQueue(self):
        self.test.qosScheduleProfileStrictCommandWithIllegalQueue()
    def test_qosScheduleProfileStrictCommandWithNullQueue(self):
        self.test.qosScheduleProfileStrictCommandWithNullQueue()
    def test_qosScheduleProfileStrictNoCommand(self):
        self.test.qosScheduleProfileStrictNoCommand()
    def test_qosScheduleProfileStrictNoCommandWithIllegalQueue(self):
        self.test.qosScheduleProfileStrictNoCommandWithIllegalQueue()
    def test_qosScheduleProfileStrictNoCommandWithNullQueue(self):
        self.test.qosScheduleProfileStrictNoCommandWithNullQueue()
    def test_qosScheduleProfileStrictNoCommandWithMissingQueue(self):
        self.test.qosScheduleProfileStrictNoCommandWithMissingQueue()
    def test_qosScheduleProfileWrrCommand(self):
        self.test.qosScheduleProfileWrrCommand()
    def test_qosScheduleProfileWrrCommandWithIllegalQueue(self):
        self.test.qosScheduleProfileWrrCommandWithIllegalQueue()
    def test_qosScheduleProfileWrrCommandWithNullQueue(self):
        self.test.qosScheduleProfileWrrCommandWithNullQueue()
    def test_qosScheduleProfileWrrCommandWithIllegalWeight(self):
        self.test.qosScheduleProfileWrrCommandWithIllegalWeight()
    def test_qosScheduleProfileWrrCommandWithNullWeight(self):
        self.test.qosScheduleProfileWrrCommandWithNullWeight()
    def test_qosScheduleProfileWrrNoCommand(self):
        self.test.qosScheduleProfileWrrNoCommand()
    def test_qosScheduleProfileWrrNoCommandWithIllegalQueue(self):
        self.test.qosScheduleProfileWrrNoCommandWithIllegalQueue()
    def test_qosScheduleProfileWrrNoCommandWithNullQueue(self):
        self.test.qosScheduleProfileWrrNoCommandWithNullQueue()
    def test_qosScheduleProfileWrrNoCommandWithIllegalWeight(self):
        self.test.qosScheduleProfileWrrNoCommandWithIllegalWeight()
    def test_qosScheduleProfileWrrNoCommandWithNullWeight(self):
        self.test.qosScheduleProfileWrrNoCommandWithNullWeight()
    def test_qosScheduleProfileWrrNoCommandWithMissingQueue(self):
        self.test.qosScheduleProfileWrrNoCommandWithMissingQueue()
    def test_qosScheduleProfileShowCommand(self):
        self.test.qosScheduleProfileShowCommand()
    def test_qosScheduleProfileShowCommandWithIllegalName(self):
        self.test.qosScheduleProfileShowCommandWithIllegalName()
    def test_qosScheduleProfileShowCommandShowsAllProfiles(self):
        self.test.qosScheduleProfileShowCommandShowsAllProfiles()
    def test_qosScheduleProfileShowCommandFactoryDefault(self):
        self.test.qosScheduleProfileShowCommandFactoryDefault()
    def test_qosScheduleProfileShowCommandWithNonExistentProfile(self):
        self.test.qosScheduleProfileShowCommandWithNonExistentProfile()