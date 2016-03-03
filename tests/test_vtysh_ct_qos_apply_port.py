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

class QosApplyPortCliTest(OpsVsiTest):
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

        s1.cmdCLI('interface 1')
        s1.cmdCLI('no lag 10')
        s1.cmdCLI('no apply qos schedule-profile')
        s1.cmdCLI('exit')

        s1.cmdCLI('interface lag 10')
        s1.cmdCLI('no apply qos schedule-profile')
        s1.cmdCLI('exit')

        s1.cmdCLI('no qos schedule-profile p1')
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('wrr queue 4 weight 40')
        s1.cmdCLI('wrr queue 5 weight 50')
        s1.cmdCLI('wrr queue 6 weight 60')
        s1.cmdCLI('wrr queue 7 weight 70')
        s1.cmdCLI('wrr queue 0 weight 1')
        s1.cmdCLI('wrr queue 1 weight 10')
        s1.cmdCLI('wrr queue 2 weight 20')
        s1.cmdCLI('wrr queue 3 weight 30')
        s1.cmdCLI('exit')

        s1.cmdCLI('end')
        s1.cmdCLI('configure terminal')

        return s1

    def qosApplyPortCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('apply qos schedule-profile p1')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'p1' in out

    def qosApplyPortCommandWithMissingScheduleProfileQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('no wrr queue 7')
        s1.cmdCLI('exit')
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('apply qos schedule-profile p1')
        assert 'cannot' in out

    def qosApplyPortCommandWithIllegalScheduleProfile(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('apply qos schedule-profile p&^%$1 ')
        assert 'allowed' in out

    def qosApplyPortCommandWithNullScheduleProfile(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('apply qos schedule-profile')
        assert 'incomplete' in out

    def qosApplyPortCommandWithInterfaceInLag(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('lag 10')
        out = s1.cmdCLI('apply qos schedule-profile p1')
        assert 'cannot' in out

    def qosApplyPortCommandWithMissingScheduleProfile(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('apply qos schedule-profile missing')
        assert 'cannot' in out

    def qosApplyPortCommandWithStrictScheduleProfile(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('apply qos schedule-profile strict')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'strict' in out

    def qosApplyPortCommandWithAllStrict(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('strict queue 4')
        s1.cmdCLI('strict queue 5')
        s1.cmdCLI('strict queue 6')
        s1.cmdCLI('strict queue 7')
        s1.cmdCLI('strict queue 0')
        s1.cmdCLI('strict queue 1')
        s1.cmdCLI('strict queue 2')
        s1.cmdCLI('strict queue 3')
        s1.cmdCLI('exit')
        s1.cmdCLI('interface 1')
        s1.cmdCLI('apply qos schedule-profile p1')
        out = s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def qosApplyPortCommandWithAllWrr(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('wrr queue 4 weight 400')
        s1.cmdCLI('wrr queue 5 weight 500')
        s1.cmdCLI('wrr queue 6 weight 600')
        s1.cmdCLI('wrr queue 7 weight 700')
        s1.cmdCLI('wrr queue 0 weight 1')
        s1.cmdCLI('wrr queue 1 weight 100')
        s1.cmdCLI('wrr queue 2 weight 200')
        s1.cmdCLI('wrr queue 3 weight 300')
        s1.cmdCLI('exit')
        s1.cmdCLI('interface 1')
        s1.cmdCLI('apply qos schedule-profile p1')
        out = s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def qosApplyPortCommandWithAllWrrWithMaxStrict(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('wrr queue 4 weight 400')
        s1.cmdCLI('wrr queue 5 weight 500')
        s1.cmdCLI('wrr queue 6 weight 600')
        s1.cmdCLI('strict queue 7')
        s1.cmdCLI('wrr queue 0 weight 1')
        s1.cmdCLI('wrr queue 1 weight 100')
        s1.cmdCLI('wrr queue 2 weight 200')
        s1.cmdCLI('wrr queue 3 weight 300')
        s1.cmdCLI('exit')
        s1.cmdCLI('interface 1')
        s1.cmdCLI('apply qos schedule-profile p1')
        out = s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def qosApplyPortCommandWithHigherStrictLowerWrr(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('strict queue 4')
        s1.cmdCLI('strict queue 5')
        s1.cmdCLI('strict queue 6')
        s1.cmdCLI('strict queue 7')
        s1.cmdCLI('wrr queue 0 weight 1')
        s1.cmdCLI('wrr queue 1 weight 100')
        s1.cmdCLI('wrr queue 2 weight 200')
        s1.cmdCLI('wrr queue 3 weight 300')
        s1.cmdCLI('exit')
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('apply qos schedule-profile p1')
        assert 'must have the same algorithm assigned to each queue' in out

    def qosApplyPortCommandWithLowerStrictHigherWrr(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('wrr queue 4 weight 400')
        s1.cmdCLI('wrr queue 5 weight 500')
        s1.cmdCLI('wrr queue 6 weight 600')
        s1.cmdCLI('wrr queue 7 weight 700')
        s1.cmdCLI('strict queue 0')
        s1.cmdCLI('strict queue 1')
        s1.cmdCLI('strict queue 2')
        s1.cmdCLI('strict queue 3')
        s1.cmdCLI('exit')
        s1.cmdCLI('interface 1')
        out = s1.cmdCLI('apply qos schedule-profile p1')
        assert 'must have the same algorithm assigned to each queue' in out

    def qosApplyPortNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('apply schedule-profile p1')
        s1.cmdCLI('no apply qos schedule-profile')
        out = s1.cmdCLI('do show running-config interface 1')
        assert 'p1' not in out

    def qosApplyPortNoCommandWithInterfaceInLag(self):
        s1 = self.setUp()
        s1.cmdCLI('interface 1')
        s1.cmdCLI('lag 10')
        out = s1.cmdCLI('no apply qos schedule-profile')
        assert 'cannot' in out

class Test_qos_apply_port_cli:
    def setup_class(cls):
        Test_qos_apply_port_cli.test = QosApplyPortCliTest()

    def teardown_class(cls):
        Test_qos_apply_port_cli.test.net.stop()

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

    def test_qosApplyPortCommand(self):
        self.test.qosApplyPortCommand()
    def test_qosApplyPortCommandWithMissingScheduleProfileQueue(self):
        self.test.qosApplyPortCommandWithMissingScheduleProfileQueue()
    def test_qosApplyPortCommandWithIllegalScheduleProfile(self):
        self.test.qosApplyPortCommandWithIllegalScheduleProfile()
    def test_qosApplyPortCommandWithNullScheduleProfile(self):
        self.test.qosApplyPortCommandWithNullScheduleProfile()
    def test_qosApplyPortCommandWithMissingScheduleProfile(self):
        self.test.qosApplyPortCommandWithMissingScheduleProfile()
    def test_qosApplyPortCommandWithStrictScheduleProfile(self):
        self.test.qosApplyPortCommandWithStrictScheduleProfile()
    def test_qosApplyPortCommandWithAllStrict(self):
        self.test.qosApplyPortCommandWithAllStrict()
    def test_qosApplyPortCommandWithAllWrr(self):
        self.test.qosApplyPortCommandWithAllWrr()
    def test_qosApplyPortCommandWithAllWrrWithMaxStrict(self):
        self.test.qosApplyPortCommandWithAllWrrWithMaxStrict()
    def test_qosApplyPortCommandWithHigherStrictLowerWrr(self):
        self.test.qosApplyPortCommandWithHigherStrictLowerWrr()
    def test_qosApplyPortCommandWithLowerStrictHigherWrr(self):
        self.test.qosApplyPortCommandWithLowerStrictHigherWrr()
    def test_qosApplyPortNoCommand(self):
        self.test.qosApplyPortNoCommand()
    def test_qosApplyPortCommandWithInterfaceInLag(self):
        self.test.qosApplyPortCommandWithInterfaceInLag()
    def test_qosApplyPortNoCommandWithInterfaceInLag(self):
        self.test.qosApplyPortNoCommandWithInterfaceInLag()
