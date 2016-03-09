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

class QosCliTest(OpsVsiTest):
    def setupNet(self):
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        topo = SingleSwitchTopo(k=0, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(topo, switch=VsiOpenSwitch,
                           host=Host, link=OpsVsiLink,
                           controller=None, build=True)

class Test_qos_cli():
    def setup_class(cls):
        Test_qos_cli.test = QosCliTest()

    def teardown_class(cls):
        Test_qos_cli.test.net.stop()

    def setup(self):
        self.s1 = Test_qos_cli.test.net.switches[0]

    def setUp_qosApplyGlobal(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('apply qos queue-profile default schedule-profile default')

        self.s1.cmdCLI('no qos queue-profile p1')
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('map queue 4 local-priority 3')
        self.s1.cmdCLI('map queue 5 local-priority 2')
        self.s1.cmdCLI('map queue 6 local-priority 1')
        self.s1.cmdCLI('map queue 7 local-priority 0')
        self.s1.cmdCLI('map queue 0 local-priority 7')
        self.s1.cmdCLI('map queue 1 local-priority 6')
        self.s1.cmdCLI('map queue 2 local-priority 5')
        self.s1.cmdCLI('map queue 3 local-priority 4')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('no qos schedule-profile p1')
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 4 weight 40')
        self.s1.cmdCLI('wrr queue 5 weight 50')
        self.s1.cmdCLI('wrr queue 6 weight 60')
        self.s1.cmdCLI('wrr queue 7 weight 70')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')

    def setUp_qosApplyPort(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('no lag 10')
        self.s1.cmdCLI('no apply qos schedule-profile')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('interface lag 10')
        self.s1.cmdCLI('no apply qos schedule-profile')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('no qos schedule-profile p1')
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 4 weight 40')
        self.s1.cmdCLI('wrr queue 5 weight 50')
        self.s1.cmdCLI('wrr queue 6 weight 60')
        self.s1.cmdCLI('wrr queue 7 weight 70')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def setUp_qosCosMap(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos cos-map 7')

    def setup_qosCosPort(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos cos')

        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('no lag 10')
        self.s1.cmdCLI('no qos trust')
        self.s1.cmdCLI('no qos cos')

        self.s1.cmdCLI('interface lag 10')
        self.s1.cmdCLI('no qos trust')
        self.s1.cmdCLI('no qos cos')

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def setUp_qosDscpMap(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos dscp-map 38')

    def setUp_qosDscpPort(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos dscp')

        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('no lag 10')
        self.s1.cmdCLI('no qos trust')
        self.s1.cmdCLI('no qos dscp')

        self.s1.cmdCLI('interface lag 10')
        self.s1.cmdCLI('no qos trust')
        self.s1.cmdCLI('no qos dscp')

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def setUp_qosQueueProfile(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('apply qos queue-profile default schedule-profile default')

        self.s1.cmdCLI('no qos queue-profile p1')

    def setUp_qosQueueStatistics(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no interface lag 10')

    def setUp_qosScheduleProfile(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('apply qos queue-profile default schedule-profile default')

        self.s1.cmdCLI('no qos schedule-profile p1')

    def setUp_qosTrustGlobal(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos trust')

    def setUp_qosTrustPort(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos trust')

        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('no lag 10')
        self.s1.cmdCLI('no qos trust')

        self.s1.cmdCLI('interface lag 10')
        self.s1.cmdCLI('no qos trust')

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def teardown(self):
        pass

    def __del__(self):
        del self.test

    def test_qosApplyGlobalCommand(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        out = self.s1.cmdCLI('do show qos queue-profile')
        assert 'applied        p1' in out
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def test_qosApplyGlobalCommandWithDuplicateQueueProfileQueue(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('map queue 0 local-priority 7')
        self.s1.cmdCLI('map queue 1 local-priority 7')
        self.s1.cmdCLI('exit')
        out = self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        assert 'assigned more than once' in out

    def test_qosApplyGlobalCommandWithMissingQueueProfileQueue(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('no map queue 7')
        self.s1.cmdCLI('exit')
        out = self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        assert 'missing' in out

    def test_qosApplyGlobalCommandWithMissingScheduleProfileQueue(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('no wrr queue 7')
        self.s1.cmdCLI('exit')
        out = self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        assert 'cannot' in out

    def test_qosApplyGlobalCommandWithIllegalQueueProfile(self):
        self.setUp_qosApplyGlobal()
        out = self.s1.cmdCLI('apply qos queue-profile p&^%$1 schedule-profile p1')
        assert 'allowed' in out

    def test_qosApplyGlobalCommandWithNullQueueProfile(self):
        self.setUp_qosApplyGlobal()
        out = self.s1.cmdCLI('apply qos queue-profile schedule-profile p1')
        assert 'Unknown command' in out

    def test_qosApplyGlobalCommandWithMissingQueueProfile(self):
        self.setUp_qosApplyGlobal()
        out = self.s1.cmdCLI('apply qos queue-profile missing schedule-profile p1')
        assert 'cannot' in out

    def test_qosApplyGlobalCommandWithIllegalScheduleProfile(self):
        self.setUp_qosApplyGlobal()
        out = self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p&^%$1 ')
        assert 'allowed' in out

    def test_qosApplyGlobalCommandWithNullScheduleProfile(self):
        self.setUp_qosApplyGlobal()
        out = self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile')
        assert 'incomplete' in out

    def test_qosApplyGlobalCommandWithMissingScheduleProfile(self):
        self.setUp_qosApplyGlobal()
        out = self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile missing')
        assert 'cannot' in out

    def test_qosApplyGlobalCommandWithStrictScheduleProfile(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('apply qos queue-profile default schedule-profile strict')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        strict' in out

    def test_qosApplyGlobalCommandWithAllStrict(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('strict queue 4')
        self.s1.cmdCLI('strict queue 5')
        self.s1.cmdCLI('strict queue 6')
        self.s1.cmdCLI('strict queue 7')
        self.s1.cmdCLI('strict queue 0')
        self.s1.cmdCLI('strict queue 1')
        self.s1.cmdCLI('strict queue 2')
        self.s1.cmdCLI('strict queue 3')
        self.s1.cmdCLI('exit')
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def test_qosApplyGlobalCommandWithAllWrr(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 4 weight 40')
        self.s1.cmdCLI('wrr queue 5 weight 50')
        self.s1.cmdCLI('wrr queue 6 weight 60')
        self.s1.cmdCLI('wrr queue 7 weight 70')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def test_qosApplyGlobalCommandWithAllWrrWithMaxStrict(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 4 weight 40')
        self.s1.cmdCLI('wrr queue 5 weight 50')
        self.s1.cmdCLI('wrr queue 6 weight 60')
        self.s1.cmdCLI('strict queue 7')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def test_qosApplyGlobalCommandWithHigherStrictLowerWrr(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('strict queue 4')
        self.s1.cmdCLI('strict queue 5')
        self.s1.cmdCLI('strict queue 6')
        self.s1.cmdCLI('strict queue 7')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')
        out = self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        assert 'must have the same algorithm assigned to each queue' in out

    def test_qosApplyGlobalCommandWithLowerStrictHigherWrr(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 4 weight 40')
        self.s1.cmdCLI('wrr queue 5 weight 50')
        self.s1.cmdCLI('wrr queue 6 weight 60')
        self.s1.cmdCLI('wrr queue 7 weight 70')
        self.s1.cmdCLI('strict queue 0')
        self.s1.cmdCLI('strict queue 1')
        self.s1.cmdCLI('strict queue 2')
        self.s1.cmdCLI('strict queue 3')
        self.s1.cmdCLI('exit')
        out = self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        assert 'must have the same algorithm assigned to each queue' in out

    def test_qosApplyGlobalCommandAndThenRestoreDefaultQueueProfile(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        self.s1.cmdCLI('qos queue-profile default')
        self.s1.cmdCLI('name queue 0 QueueName')
        out = self.s1.cmdCLI('do show qos queue-profile default')
        assert 'QueueName' in out
        self.s1.cmdCLI('no qos queue-profile default')
        out = self.s1.cmdCLI('do show qos queue-profile default')
        assert 'QueueName' not in out

    def test_qosApplyGlobalCommandAndThenRestoreDefaultScheduleProfile(self):
        self.setUp_qosApplyGlobal()
        self.s1.cmdCLI('apply qos queue-profile p1 schedule-profile p1')
        self.s1.cmdCLI('qos schedule-profile default')
        self.s1.cmdCLI('strict queue 0')
        out = self.s1.cmdCLI('do show qos schedule-profile default')
        assert '0         strict' in out
        self.s1.cmdCLI('no qos schedule-profile default')
        out = self.s1.cmdCLI('do show qos schedule-profile default')
        assert '0         strict' not in out
        self.setUp_qosApplyGlobal()

    def test_qosApplyPortCommand(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('apply qos schedule-profile p1')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def test_qosApplyPortCommandWithMissingScheduleProfileQueue(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('no wrr queue 7')
        self.s1.cmdCLI('exit')
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('apply qos schedule-profile p1')
        assert 'cannot' in out

    def test_qosApplyPortCommandWithIllegalScheduleProfile(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('apply qos schedule-profile p&^%$1 ')
        assert 'allowed' in out

    def test_qosApplyPortCommandWithNullScheduleProfile(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('apply qos schedule-profile')
        assert 'incomplete' in out

    def test_qosApplyPortCommandWithInterfaceInLag(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('lag 10')
        out = self.s1.cmdCLI('apply qos schedule-profile p1')
        assert 'cannot' in out

    def test_qosApplyPortCommandWithMissingScheduleProfile(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('apply qos schedule-profile missing')
        assert 'cannot' in out

    def test_qosApplyPortCommandWithStrictScheduleProfile(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('apply qos schedule-profile strict')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        strict' in out

    def test_qosApplyPortCommandWithAllStrict(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('strict queue 4')
        self.s1.cmdCLI('strict queue 5')
        self.s1.cmdCLI('strict queue 6')
        self.s1.cmdCLI('strict queue 7')
        self.s1.cmdCLI('strict queue 0')
        self.s1.cmdCLI('strict queue 1')
        self.s1.cmdCLI('strict queue 2')
        self.s1.cmdCLI('strict queue 3')
        self.s1.cmdCLI('exit')
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('apply qos schedule-profile p1')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def test_qosApplyPortCommandWithAllWrr(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 4 weight 40')
        self.s1.cmdCLI('wrr queue 5 weight 50')
        self.s1.cmdCLI('wrr queue 6 weight 60')
        self.s1.cmdCLI('wrr queue 7 weight 70')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('apply qos schedule-profile p1')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def test_qosApplyPortCommandWithAllWrrWithMaxStrict(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 4 weight 40')
        self.s1.cmdCLI('wrr queue 5 weight 50')
        self.s1.cmdCLI('wrr queue 6 weight 60')
        self.s1.cmdCLI('strict queue 7')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('apply qos schedule-profile p1')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied        p1' in out

    def test_qosApplyPortCommandWithHigherStrictLowerWrr(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('strict queue 4')
        self.s1.cmdCLI('strict queue 5')
        self.s1.cmdCLI('strict queue 6')
        self.s1.cmdCLI('strict queue 7')
        self.s1.cmdCLI('wrr queue 0 weight 1')
        self.s1.cmdCLI('wrr queue 1 weight 10')
        self.s1.cmdCLI('wrr queue 2 weight 20')
        self.s1.cmdCLI('wrr queue 3 weight 30')
        self.s1.cmdCLI('exit')
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('apply qos schedule-profile p1')
        assert 'must have the same algorithm assigned to each queue' in out

    def test_qosApplyPortCommandWithLowerStrictHigherWrr(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 4 weight 40')
        self.s1.cmdCLI('wrr queue 5 weight 50')
        self.s1.cmdCLI('wrr queue 6 weight 60')
        self.s1.cmdCLI('wrr queue 7 weight 70')
        self.s1.cmdCLI('strict queue 0')
        self.s1.cmdCLI('strict queue 1')
        self.s1.cmdCLI('strict queue 2')
        self.s1.cmdCLI('strict queue 3')
        self.s1.cmdCLI('exit')
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('apply qos schedule-profile p1')
        assert 'must have the same algorithm assigned to each queue' in out

    def test_qosApplyPortNoCommand(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('apply schedule-profile p1')
        self.s1.cmdCLI('no apply qos schedule-profile')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'complete       p1' in out

    def test_qosApplyPortNoCommandWithInterfaceInLag(self):
        self.setUp_qosApplyPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('lag 10')
        out = self.s1.cmdCLI('no apply qos schedule-profile')
        assert 'cannot' in out
        self.setUp_qosApplyPort()

    def test_qosCosMapCommand(self):
        self.setUp_qosCosMap()
        self.s1.cmdCLI('qos cos-map 7 local-priority 1 color red name MyName1')
        self.s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos cos-map')
        assert '7          2              yellow  MyName2' in out

    def test_qosCosMapCommandWithIllegalCodePoint(self):
        self.setUp_qosCosMap()
        out = self.s1.cmdCLI('qos cos-map -1 local-priority 2 color yellow name MyName2')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('qos cos-map 8 local-priority 2 color yellow name MyName2')
        assert 'Unknown command' in out

    def test_qosCosMapCommandWithNullCodePoint(self):
        self.setUp_qosCosMap()
        out = self.s1.cmdCLI('qos cos-map local-priority 2 color yellow name MyName2')
        assert 'Unknown command' in out

    def get_max_local_priority(self, printed_show_output):
        max_local_priority = -1
        lines = printed_show_output.split('\n')
        for line in lines:
            if line[0].isdigit():
                local_priority = line.split(' ')[1]
                if local_priority > max_local_priority:
                    max_local_priority = local_priority
        return max_local_priority

    def test_qosCosMapCommandWithIllegalLocalPriority(self):
        self.setUp_qosCosMap()
        out = self.s1.cmdCLI('do show qos cos-map default')
        max_local_priority = self.get_max_local_priority(out)

        out = self.s1.cmdCLI('qos cos-map 7 local-priority -1 color yellow name MyName2')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('qos cos-map 7 local-priority ' + \
            str(max_local_priority) + ' color yellow name MyName2')
        assert 'Unknown command' in out

    def test_qosCosMapCommandWithNullLocalPriority(self):
        self.setUp_qosCosMap()
        out = self.s1.cmdCLI('qos cos-map 7 color yellow name MyName2')
        assert 'Unknown command' in out

    def test_qosCosMapCommandWithIllegalColor(self):
        self.setUp_qosCosMap()
        out = self.s1.cmdCLI('qos cos-map 7 local-priority 2 name MyName2 color illegal')
        assert 'Unknown command' in out

    def test_qosCosMapCommandWithNullColor(self):
        self.setUp_qosCosMap()
        out = self.s1.cmdCLI('qos cos-map 7 local-priority 2 name MyName2')
        out = self.s1.cmdCLI('do show qos cos-map')
        assert '7          2              green   MyName2' in out

        out = self.s1.cmdCLI('qos cos-map 7 local-priority 2 name MyName2 color')
        assert 'incomplete.' in out

    def test_qosCosMapCommandWithIllegalName(self):
        self.setUp_qosCosMap()
        out = self.s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow '
                'name NameThatIsLongerThan64Characterssssssssssssssssssssssssssssssssss')
        assert 'allowed' in out

    def test_qosCosMapCommandWithNullName(self):
        self.setUp_qosCosMap()
        out = self.s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow')
        out = self.s1.cmdCLI('do show qos cos-map')
        assert '7          2              yellow' in out

        out = self.s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow name')
        assert 'incomplete.' in out

    def test_qosCosMapNoCommand(self):
        self.setUp_qosCosMap()
        self.s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow name MyName2')
        self.s1.cmdCLI('no qos cos-map 7')
        out = self.s1.cmdCLI('do show qos cos-map')
        assert '7          7              green   Network_Control' in out

    def test_qosCosMapShowCommand(self):
        self.setUp_qosCosMap()
        self.s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos cos-map')
        assert '7          2              yellow  MyName2' in out

    def test_qosCosMapShowCommandWithDefault(self):
        self.setUp_qosCosMap()
        self.s1.cmdCLI('qos cos-map 7 local-priority 2 color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos cos-map default')
        assert '7          7              green   Network_Control' in out

    def test_qosCosMapShowRunningConfigWithDefault(self):
        self.setUp_qosCosMap()
        self.s1.cmdCLI('qos cos-map 1 local-priority 0 color green name "Background"')
        out = self.s1.cmdCLI('do show running-config')
        assert 'code_point' not in out
        assert 'local_priority' not in out
        assert 'color' not in out
        assert 'name' not in out
        self.setUp_qosCosMap()

    def test_qosCosPortCommand(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos cos 1')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'override 1' in out

    def test_qosCosPortCommandWithTrustEmpty(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('qos cos 1')
        assert 'only allowed' in out

    def test_qosCosPortCommandWithTrustCos(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust cos')
        out = self.s1.cmdCLI('qos cos 1')
        assert 'only allowed' in out

    def test_qosCosPortCommandWithIllegalQosCos(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('qos cos 8')
        assert 'Unknown command' in out

    def test_qosCosPortCommandWithNullQosCos(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('qos cos')
        assert 'Command incomplete' in out

    def test_qosCosPortCommandWithInterfaceInLag(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('lag 10')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('qos cos 1')
        assert 'cannot' in out

    def test_qosCosPortNoCommand(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos cos 1')
        self.s1.cmdCLI('no qos cos')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'override' not in out

    def test_qosCosPortNoCommandWithInterfaceInLag(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('lag 10')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('no qos cos')
        assert 'cannot' in out

    def test_qosCosPortShowRunningConfig(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos cos 1')
        out = self.s1.cmdCLI('do show running-config')
        assert 'override' in out

    def test_qosCosPortShowRunningConfigInterface(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos cos 1')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'override' in out

    def test_qosCosPortShowInterface(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos cos 1')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'override' in out
        self.setup_qosCosPort()

    def test_qosDscpMapCommand(self):
        self.setUp_qosDscpMap()
        self.s1.cmdCLI(
            'qos dscp-map 38 local-priority 1 color green name MyName1')
        self.s1.cmdCLI(
            'qos dscp-map 38 local-priority 2 color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos dscp-map')
        assert '38         2              yellow  MyName2' in out

    def test_qosDscpMapCommandWithIllegalCodePoint(self):
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI(
            'qos dscp-map -1 local-priority 2 cos 3 color yellow name MyName2')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI(
            'qos dscp-map 64 local-priority 2 cos 3 color yellow name MyName2')
        assert 'Unknown command' in out

    def test_qosDscpMapCommandWithNullCodePoint(self):
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI(
            'qos dscp-map local-priority 2 cos 3 color yellow name MyName2')
        assert 'Unknown command' in out

    def test_qosDscpMapCommandWithIllegalLocalPriority(self):
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI('do show qos dscp-map default')
        max_local_priority = self.get_max_local_priority(out)

        out = self.s1.cmdCLI('qos dscp-map 38 local-priority -1 color yellow name MyName2')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('qos dscp-map 38 local-priority ' + \
            str(max_local_priority) + ' color yellow name MyName2')
        assert 'Unknown command' in out

    def test_qosDscpMapCommandWithNullLocalPriority(self):
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI('qos dscp-map 38 cos 3 color yellow name MyName2')
        assert 'Unknown command' in out

    def test_qosDscpMapCommandWithIllegalCos(self):
        # The cos option is not supported in dill.
        return
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI(
            'qos dscp-map 38 local-priority 2 cos 8 color yellow name MyName2')
        assert 'Unknown command' in out

    def test_qosDscpMapCommandWithNullCos(self):
        # The cos option is not supported in dill.
        return
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI(
            'qos dscp-map 38 local-priority 2 color yellow name MyName2')
        out = self.s1.cmdCLI('do show running-config')
        assert 'code_point 38' in out
        assert 'local_priority 2' in out
        assert 'cos <empty>' in out
        assert 'color yellow' in out
        assert 'name MyName2' in out

    def test_qosDscpMapCommandWithIllegalColor(self):
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI(
            'qos dscp-map 38 local-priority 2 name MyName2 color illegal')
        assert 'Unknown command' in out

    def test_qosDscpMapCommandWithNullColor(self):
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI('qos dscp-map 38 local-priority 2 name MyName2')
        out = self.s1.cmdCLI('do show qos dscp-map')
        assert '38         2              green   MyName2 ' in out

        out = self.s1.cmdCLI('qos dscp-map 38 local-priority 2 name MyName2 color')
        assert 'incomplete.' in out

    def test_qosDscpMapCommandWithIllegalName(self):
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI('qos dscp-map 38 local-priority 2 color yellow '
                        'name NameThatIsLongerThan64Characterssssssssssssssssssssssssssssssssss')
        assert 'allowed' in out

    def test_qosDscpMapCommandWithNullName(self):
        self.setUp_qosDscpMap()
        out = self.s1.cmdCLI('qos dscp-map 38 local-priority 2 color yellow')
        out = self.s1.cmdCLI('do show qos dscp-map')
        assert '38         2              yellow' in out

        out = self.s1.cmdCLI('qos dscp-map 38 local-priority 2 color green name')
        assert 'incomplete.' in out

    def test_qosDscpMapNoCommand(self):
        self.setUp_qosDscpMap()
        self.s1.cmdCLI('qos dscp-map 38 local-priority 2 color yellow name MyName2')
        self.s1.cmdCLI('no qos dscp-map 38')
        out = self.s1.cmdCLI('do show qos dscp-map')
        assert '38         4              red     AF43' in out

    def test_qosDscpMapShowCommand(self):
        self.setUp_qosDscpMap()
        self.s1.cmdCLI('qos dscp-map 38 local-priority 2 color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos dscp-map')
        assert '38         2              yellow  MyName2' in out

    def test_qosDscpMapShowCommandWithDefault(self):
        self.setUp_qosDscpMap()
        self.s1.cmdCLI('qos dscp-map 38 local-priority 2 color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos dscp-map default')
        assert '38         4              red     AF43' in out

    def test_qosDscpMapShowRunningConfigWithDefault(self):
        self.setUp_qosDscpMap()
        self.s1.cmdCLI('qos dscp-map 38 local-priority 4 cos 4 color red name AF43')
        out = self.s1.cmdCLI('do show running-config')
        assert 'code_point' not in out
        assert 'local_priority' not in out
        assert 'cos' not in out
        assert 'color' not in out
        assert 'name' not in out
        self.setUp_qosDscpMap()

    def test_qosDscpPortCommand(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos dscp 1')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'override 1' in out

    def test_qosDscpPortCommandWithTrustEmpty(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('qos dscp 1')
        assert 'only allowed' in out

    def test_qosDscpPortCommandWithTrustDscp(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('qos dscp 1')
        assert 'only allowed' in out

    def test_qosDscpPortCommandWithIllegalQosDscp(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('qos dscp -1')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('qos dscp 64')
        assert 'Unknown command' in out

    def test_qosDscpPortCommandWithNullQosDscp(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('qos dscp')
        assert 'Command incomplete' in out

    def test_qosDscpPortCommandWithInterfaceInLag(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('lag 10')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('qos dscp 1')
        assert 'cannot' in out

    def test_qosDscpPortNoCommand(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos dscp 1')
        self.s1.cmdCLI('no qos dscp')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'override' not in out

    def test_qosDscpPortNoCommandWithInterfaceInLag(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('lag 10')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('no qos dscp')
        assert 'cannot' in out

    def test_qosDscpPortShowRunningConfig(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos dscp 1')
        out = self.s1.cmdCLI('do show running-config')
        assert 'override' in out

    def test_qosDscpPortShowRunningConfigInterface(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos dscp 1')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'override' in out

    def test_qosDscpPortShowInterface(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos dscp 1')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'override' in out
        self.setUp_qosDscpPort()

    def test_qosQueueProfileCommand(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('do show qos queue-profile')
        assert 'p1' in out

    def test_qosQueueProfileCommandWithIllegalName(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('qos queue-profile p^%$#1')
        assert 'allowed' in out

    def test_qosQueueProfileCommandWithNullName(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('qos queue-profile')
        assert 'incomplete' in out

    def test_qosQueueProfileCommandWithStrictName(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('qos queue-profile strict')
        assert 'cannot' in out

    def test_qosQueueProfileCommandWithAppliedProfile(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('qos queue-profile default')
        assert 'cannot' in out

    def test_qosQueueProfileNoCommand(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('no qos queue-profile p1')
        out = self.s1.cmdCLI('do show qos queue-profile')
        assert 'p1' not in out

    def test_qosQueueProfileNoCommandWithIllegalName(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('no qos queue-profile p^%$#1')
        assert 'allowed' in out

    def test_qosQueueProfileNoCommandWithNullName(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('no qos queue-profile')
        assert 'incomplete' in out

    def test_qosQueueProfileNoCommandWithStrictName(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('no qos queue-profile strict')
        assert 'cannot' in out

    def test_qosQueueProfileNoCommandWithAppliedProfile(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('no qos queue-profile default')
        assert 'cannot' in out

    def test_qosQueueProfileNoCommandWithNonExistentProfile(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('no qos queue-profile NonExistent')
        assert 'does not exist' in out

    def test_qosQueueProfileNameCommand(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('name queue 1 QueueName')
        out = self.s1.cmdCLI('do show qos queue-profile p1')
        assert 'QueueName' in out

    def test_qosQueueProfileNameCommandWithIllegalName(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('name queue 1 Queue^%$#Name')
        assert 'allowed' in out

    def test_qosQueueProfileNameCommandWithNullName(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('name queue 1')
        assert 'incomplete' in out

    def test_qosQueueProfileNameCommandWithIllegalQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('name queue -1 QueueName')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('name queue 8 QueueName')
        assert 'Unknown command' in out

    def test_qosQueueProfileNameCommandWithNullQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('name queue QueueName')
        assert 'Unknown command' in out

    def test_qosQueueProfileNameNoCommand(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('name queue 1 QueueName')
        self.s1.cmdCLI('no name queue 1')
        out = self.s1.cmdCLI('do show qos queue-profile p1')
        assert 'QueueName' not in out

    def test_qosQueueProfileNameNoCommandWithIllegalQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('no name queue -1')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('no name queue 8')
        assert 'Unknown command' in out

    def test_qosQueueProfileNameNoCommandWithNullQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('no name queue')
        assert 'incomplete' in out

    def test_qosQueueProfileNameNoCommandWithMissingQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('no name queue 2')
        assert 'does not have queue_num' in out

    def test_qosQueueProfileMapCommand(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('map queue 1 local-priority 2')
        out = self.s1.cmdCLI('do show qos queue-profile p1')
        assert '2' in out

    def test_qosQueueProfileMapCommandWithIllegalQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('map queue -1 local-priority 2')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('map queue 8 local-priority 2')
        assert 'Unknown command' in out

    def test_qosQueueProfileMapCommandWithNullQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('map queue local-priority 2')
        assert 'Unknown command' in out

    def test_qosQueueProfileMapCommandWithIllegalPriority(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('map queue 1 local-priority -1')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('map queue 1 local-priority 8')
        assert 'Unknown command' in out

    def test_qosQueueProfileMapCommandWithNullPriority(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('map queue 1 local-priority')
        assert 'incomplete' in out

    def test_qosQueueProfileMapNoCommand(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('map queue 1 local-priority 2')
        self.s1.cmdCLI('no map queue 1 local-priority 2')
        out = self.s1.cmdCLI('do show qos queue-profile p1')
        assert '1         2' not in out

    def test_qosQueueProfileMapNoCommandWithIllegalQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('no map queue -1 local-priority 2')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('no map queue 8 local-priority 2')
        assert 'Unknown command' in out

    def test_qosQueueProfileMapNoCommandWithNullQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('no map queue local-priority 2')
        assert 'Unknown command' in out

    def test_qosQueueProfileMapNoCommandWithIllegalPriority(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('no map queue 1 local-priority -1')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('no map queue 1 local-priority 8')
        assert 'Unknown command' in out

    def test_qosQueueProfileMapNoCommandWithNullPriority(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('no map queue 1 local-priority')
        assert 'incomplete' in out

    def test_qosQueueProfileMapNoCommandDeletesSinglePriority(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('map queue 1 local-priority 2')
        self.s1.cmdCLI('map queue 1 local-priority 3')
        self.s1.cmdCLI('no map queue 1 local-priority 2')
        out = self.s1.cmdCLI('do show qos queue-profile p1')
        assert '1         3' in out

    def test_qosQueueProfileMapNoCommandDeletesAllPriorities(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('map queue 1 local-priority 2')
        self.s1.cmdCLI('map queue 1 local-priority 3')
        self.s1.cmdCLI('no map queue 1')
        out = self.s1.cmdCLI('do show qos queue-profile p1')
        assert '1         2' not in out
        assert '1         3' not in out

    def test_qosQueueProfileMapNoCommandWithMissingQueue(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        out = self.s1.cmdCLI('no map queue 2')
        assert 'does not have queue_num' in out

    def test_qosQueueProfileShowCommand(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('name queue 1 QueueName')
        out = self.s1.cmdCLI('do show qos queue-profile p1')
        assert 'QueueName' in out

    def test_qosQueueProfileShowCommandWithIllegalName(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('do show qos queue-profile p^%$#1')
        assert 'allowed' in out

    def test_qosQueueProfileShowCommandShowsAllProfiles(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('do show qos queue-profile')
        assert 'applied' in out
        assert 'default' in out

    def test_qosQueueProfileShowCommandFactoryDefault(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('do show qos queue-profile factory-default')
        assert 'queue_num' in out

    def test_qosQueueProfileShowCommandWithNonExistentProfile(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('do show qos queue-profile NonExistent')
        assert 'does not exist' in out
        self.setUp_qosQueueProfile()

    def test_qosShowQueueStatisticsCommandWithSingleInterface(self):
        self.setUp_qosQueueStatistics()
        out = self.s1.cmdCLI('do show interface 1 queues')
        assert 'Q0' in out
        assert 'Q1' in out
        assert 'Q2' in out
        assert 'Q3' in out
        assert 'Q4' in out
        assert 'Q5' in out
        assert 'Q6' in out
        assert 'Q7' in out

    def test_qosShowQueueStatisticsCommandWithAllInterfaces(self):
        self.setUp_qosQueueStatistics()
        out = self.s1.cmdCLI('do show interface queues')
        assert 'Q0' in out
        assert 'Q1' in out
        assert 'Q2' in out
        assert 'Q3' in out
        assert 'Q4' in out
        assert 'Q5' in out
        assert 'Q6' in out
        assert 'Q7' in out
        self.setUp_qosQueueStatistics()

    def test_qosScheduleProfileCommand(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'p1' in out

    def test_qosScheduleProfileCommandWithIllegalName(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('qos schedule-profile p^%$#1')
        assert 'allowed' in out

    def test_qosScheduleProfileCommandWithNullName(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('qos schedule-profile')
        assert 'incomplete' in out

    def test_qosScheduleProfileCommandWithStrictName(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('qos schedule-profile strict')
        assert 'cannot' in out

    def test_qosScheduleProfileCommandWithAppliedProfile(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('qos schedule-profile default')
        assert 'cannot' in out

    def test_qosScheduleProfileNoCommand(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('no qos schedule-profile p1')
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'p1' not in out

    def test_qosScheduleProfileNoCommandWithIllegalName(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('no qos schedule-profile p^%$#1')
        assert 'allowed' in out

    def test_qosScheduleProfileNoCommandWithNullName(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('no qos schedule-profile')
        assert 'incomplete' in out

    def test_qosScheduleProfileNoCommandWithStrictName(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('no qos schedule-profile strict')
        assert 'cannot' in out

    def test_qosScheduleProfileNoCommandWithAppliedProfile(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('no qos schedule-profile default')
        assert 'cannot' in out

    def test_qosScheduleProfileNoCommandWithNonExistentProfile(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('no qos schedule-profile NonExistent')
        assert 'does not exist' in out

    def test_qosScheduleProfileStrictCommand(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('strict queue 1')
        out = self.s1.cmdCLI('do show qos schedule-profile p1')
        assert 'strict' in out
        assert '1' in out

    def test_qosScheduleProfileStrictCommandWithIllegalQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('strict queue -1')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('strict queue 8')
        assert 'Unknown command' in out

    def test_qosScheduleProfileStrictCommandWithNullQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('strict queue')
        assert 'incomplete' in out

    def test_qosScheduleProfileStrictNoCommand(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('strict queue 1')
        self.s1.cmdCLI('no strict queue 1')
        out = self.s1.cmdCLI('do show qos schedule-profile p1')
        assert 'strict' not in out

    def test_qosScheduleProfileStrictNoCommandWithIllegalQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('no strict queue -1')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('no strict queue 8')
        assert 'Unknown command' in out

    def test_qosScheduleProfileStrictNoCommandWithNullQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('no strict queue')
        assert 'incomplete' in out

    def test_qosScheduleProfileStrictNoCommandWithMissingQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('no strict queue 2')
        assert 'does not have queue_num' in out

    def test_qosScheduleProfileWrrCommand(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 1 weight 2')
        out = self.s1.cmdCLI('do show qos schedule-profile p1')
        assert '1' in out
        assert 'weight' in out
        assert '2' in out

    def test_qosScheduleProfileWrrCommandWithIllegalQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('wrr queue -1 weight 2')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('wrr queue 8 weight 2')
        assert 'Unknown command' in out

    def test_qosScheduleProfileWrrCommandWithNullQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('wrr queue weight 2')
        assert 'Unknown command' in out

    def test_qosScheduleProfileWrrCommandWithIllegalWeight(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('wrr queue 1 weight 0')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('wrr queue 1 weight 128')
        assert 'Unknown command' in out

    def test_qosScheduleProfileWrrCommandWithNullWeight(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('wrr queue 1 weight')
        assert 'incomplete' in out

    def test_qosScheduleProfileWrrNoCommand(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('wrr queue 1 weight 2')
        self.s1.cmdCLI('no wrr queue 1')
        out = self.s1.cmdCLI('do show qos schedule-profile p1')
        assert '1         wrr' not in out

    def test_qosScheduleProfileWrrNoCommandWithIllegalQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('no wrr queue -1 weight 2')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('no wrr queue 8 weight 2')
        assert 'Unknown command' in out

    def test_qosScheduleProfileWrrNoCommandWithNullQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('no wrr queue weight 2')
        assert 'Unknown command' in out

    def test_qosScheduleProfileWrrNoCommandWithIllegalWeight(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('no wrr queue 1 weight 0')
        assert 'Unknown command' in out
        out = self.s1.cmdCLI('no wrr queue 1 weight 128')
        assert 'Unknown command' in out

    def test_qosScheduleProfileWrrNoCommandWithNullWeight(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('no wrr queue 1 weight')
        assert 'incomplete' in out

    def test_qosScheduleProfileWrrNoCommandWithMissingQueue(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        out = self.s1.cmdCLI('no wrr queue 2')
        assert 'does not have queue_num' in out

    def test_qosScheduleProfileShowCommand(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('strict queue 1')
        out = self.s1.cmdCLI('do show qos schedule-profile p1')
        assert 'strict' in out
        assert '1' in out

    def test_qosScheduleProfileShowCommandWithIllegalName(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('do show qos schedule-profile p^%$#1')
        assert 'allowed' in out

    def test_qosScheduleProfileShowCommandShowsAllProfiles(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'applied' in out
        assert 'default' in out

    def test_qosScheduleProfileShowCommandFactoryDefault(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('do show qos schedule-profile factory-default')
        assert 'queue_num' in out

    def test_qosScheduleProfileShowCommandWithNonExistentProfile(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('do show qos schedule-profile NonExistent')
        assert 'does not exist' in out
        self.setUp_qosScheduleProfile()

    def test_qosTrustGlobalCommand(self):
        self.setUp_qosTrustGlobal()
        self.s1.cmdCLI('qos trust dscp')
        self.s1.cmdCLI('qos trust cos')
        out = self.s1.cmdCLI('do show qos trust')
        assert 'qos trust cos' in out

    def test_qosTrustGlobalCommandWithIllegalQosTrust(self):
        self.setUp_qosTrustGlobal()
        out = self.s1.cmdCLI('qos trust illegal')
        assert 'Unknown command' in out

    def test_qosTrustGlobalCommandWithNullQosTrust(self):
        self.setUp_qosTrustGlobal()
        out = self.s1.cmdCLI('qos trust')
        assert 'Command incomplete' in out

    def test_qosTrustGlobalNoCommand(self):
        self.setUp_qosTrustGlobal()
        self.s1.cmdCLI('qos trust dscp')
        self.s1.cmdCLI('no qos trust')
        out = self.s1.cmdCLI('do show qos trust')
        assert 'qos trust none' in out

    def test_qosTrustGlobalShowCommand(self):
        self.setUp_qosTrustGlobal()
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show qos trust')
        assert 'qos trust dscp' in out
        self.setUp_qosTrustGlobal()

    def test_qosTrustGlobalShowCommandWithDefault(self):
        self.setUp_qosTrustGlobal()
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show qos trust default')
        assert 'qos trust none' in out

    def test_qosTrustGlobalShowRunningConfigWithDefault(self):
        self.setUp_qosTrustGlobal()
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('do show running-config')
        assert 'qos trust' not in out
        self.setUp_qosTrustGlobal()

    def test_qosTrustPortCommand(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust dscp')
        self.s1.cmdCLI('qos trust cos')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'qos trust cos' in out

    def test_qosTrustPortCommandWithIllegalQosTrust(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('qos trust illegal')
        assert 'Unknown command' in out

    def test_qosTrustPortCommandWithNullQosTrust(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        out = self.s1.cmdCLI('qos trust')
        assert 'Command incomplete' in out

    def test_qosTrustPortCommandWithInterfaceInLag(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('lag 10')
        out = self.s1.cmdCLI('qos trust cos')
        assert 'QoS Trust cannot be configured on a member of a LAG' in out

    def test_qosTrustPortNoCommand(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust dscp')
        self.s1.cmdCLI('no qos trust')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'qos trust none' in out

    def test_qosTrustPortNoCommandWithInterfaceInLag(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('lag 10')
        out = self.s1.cmdCLI('no qos trust')
        assert 'QoS Trust cannot be configured on a member of a LAG' in out

    def test_qosTrustPortShowRunningConfigWithDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('do show running-config')
        assert 'qos trust' in out

    def test_qosTrustPortShowRunningConfigWithNonDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show running-config')
        assert 'qos trust dscp' in out

    def test_qosTrustPortShowRunningConfigInterfaceWithDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'qos trust' in out

    def test_qosTrustPortShowRunningConfigInterfaceWithNonDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'qos trust dscp' in out

    def test_qosTrustPortShowInterfaceWithDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'qos trust none' in out

    def test_qosTrustPortShowInterfaceWithNonDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'qos trust dscp' in out
        self.setUp_qosTrustPort()
