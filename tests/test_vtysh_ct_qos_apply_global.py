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

class QosApplyGlobalCliTest(OpsVsiTest):
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

        s1.cmdCLI('apply qos queue-profile default schedule-profile default')

        s1.cmdCLI('no qos queue-profile p1')
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('map queue 4 local-priority 3')
        s1.cmdCLI('map queue 5 local-priority 2')
        s1.cmdCLI('map queue 6 local-priority 1')
        s1.cmdCLI('map queue 7 local-priority 0')
        s1.cmdCLI('map queue 0 local-priority 7')
        s1.cmdCLI('map queue 1 local-priority 6')
        s1.cmdCLI('map queue 2 local-priority 5')
        s1.cmdCLI('map queue 3 local-priority 4')
        s1.cmdCLI('exit')

        s1.cmdCLI('no qos schedule-profile p1')
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

        return s1

    def qosApplyGlobalCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        out = s1.cmdCLI('do show running-config')
        assert 'p1' in out

    def qosApplyGlobalCommandWithMissingQueueProfileQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('no map queue 7')
        s1.cmdCLI('exit')
        out = s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        assert 'incomplete' in out

    def qosApplyGlobalCommandWithMissingScheduleProfileQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos schedule-profile p1')
        s1.cmdCLI('no wrr queue 7')
        s1.cmdCLI('exit')
        out = s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        assert 'cannot' in out

    def qosApplyGlobalCommandWithIllegalQueueProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('apply qos queue-profile p&^%$1 schedule-profile p1')
        assert 'allowed' in out

    def qosApplyGlobalCommandWithNullQueueProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('apply qos queue-profile schedule-profile p1')
        assert 'Unknown command' in out

    def qosApplyGlobalCommandWithMissingQueueProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('apply qos queue-profile missing schedule-profile p1')
        assert 'cannot' in out

    def qosApplyGlobalCommandWithIllegalScheduleProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('apply qos queue-profile p1 schedule-profile p&^%$1 ')
        assert 'allowed' in out

    def qosApplyGlobalCommandWithNullScheduleProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('apply qos queue-profile p1 schedule-profile')
        assert 'incomplete' in out

    def qosApplyGlobalCommandWithMissingScheduleProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('apply qos queue-profile p1 schedule-profile missing')
        assert 'cannot' in out

    def qosApplyGlobalCommandWithStrictScheduleProfile(self):
        s1 = self.setUp()
        s1.cmdCLI('apply qos queue-profile p1 schedule-profile strict')
        out = s1.cmdCLI('do show running-config')
        assert 'strict' in out

    def qosApplyGlobalCommandWithAllStrict(self):
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
        s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        out = s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        "p1"' in out

    def qosApplyGlobalCommandWithAllWrr(self):
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
        s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        out = s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        "p1"' in out

    def qosApplyGlobalCommandWithAllWrrWithMaxStrict(self):
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
        s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        out = s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        "p1"' in out

    def qosApplyGlobalCommandWithHigherStrictLowerWrr(self):
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
        out = s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        assert 'incomplete' in out

    def qosApplyGlobalCommandWithLowerStrictHigherWrr(self):
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
        out = s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        assert 'incomplete' in out

    def qosApplyGlobalCommandAndThenRestoreDefaultQueueProfile(self):
        s1 = self.setUp()
        s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        s1.cmdCLI('qos queue-profile default')
        s1.cmdCLI('name queue 0 QueueName')
        s1.cmdCLI('no qos queue-profile default')
        out = s1.cmdCLI('do show qos queue-profile default')
        assert 'QueueName' not in out

    def qosApplyGlobalCommandAndThenRestoreDefaultScheduleProfile(self):
        s1 = self.setUp()
        s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        s1.cmdCLI('qos schedule-profile default')
        s1.cmdCLI('strict queue 0')
        s1.cmdCLI('no qos schedule-profile default')
        out = s1.cmdCLI('do show qos schedule-profile default')
        assert '0         strict' not in out

class Test_qos_apply_global_cli:
    def setup_class(cls):
        Test_qos_apply_global_cli.test = QosApplyGlobalCliTest()

    def teardown_class(cls):
        Test_qos_apply_global_cli.test.net.stop()

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

    def test_qosApplyGlobalCommand(self):
        self.test.qosApplyGlobalCommand()

    def test_qosApplyGlobalCommandWithMissingQueueProfileQueue(self):
        self.test.qosApplyGlobalCommandWithMissingQueueProfileQueue()

    def test_qosApplyGlobalCommandWithMissingScheduleProfileQueue(self):
        self.test.qosApplyGlobalCommandWithMissingScheduleProfileQueue()

    def test_qosApplyGlobalCommandWithIllegalQueueProfile(self):
        self.test.qosApplyGlobalCommandWithIllegalQueueProfile()

    def test_qosApplyGlobalCommandWithNullQueueProfile(self):
        self.test.qosApplyGlobalCommandWithNullQueueProfile()

    def test_qosApplyGlobalCommandWithMissingQueueProfile(self):
        self.test.qosApplyGlobalCommandWithMissingQueueProfile()

    def test_qosApplyGlobalCommandWithIllegalScheduleProfile(self):
        self.test.qosApplyGlobalCommandWithIllegalScheduleProfile()

    def test_qosApplyGlobalCommandWithNullScheduleProfile(self):
        self.test.qosApplyGlobalCommandWithNullScheduleProfile()

    def test_qosApplyGlobalCommandWithMissingScheduleProfile(self):
        self.test.qosApplyGlobalCommandWithMissingScheduleProfile()

    def test_qosApplyGlobalCommandWithStrictScheduleProfile(self):
        self.test.qosApplyGlobalCommandWithStrictScheduleProfile()

    def test_qosApplyGlobalCommandWithAllStrict(self):
        self.test.qosApplyGlobalCommandWithAllStrict()

    def test_qosApplyGlobalCommandWithAllWrr(self):
        self.test.qosApplyGlobalCommandWithAllWrr()

    def test_qosApplyGlobalCommandWithAllWrrWithMaxStrict(self):
        self.test.qosApplyGlobalCommandWithAllWrrWithMaxStrict()

    def test_qosApplyGlobalCommandWithHigherStrictLowerWrr(self):
        self.test.qosApplyGlobalCommandWithHigherStrictLowerWrr()

    def test_qosApplyGlobalCommandWithLowerStrictHigherWrr(self):
        self.test.qosApplyGlobalCommandWithLowerStrictHigherWrr()
