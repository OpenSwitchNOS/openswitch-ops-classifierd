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

class QosQueueProfileCliTest(OpsVsiTest):
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

        s1.cmdCLI('no qos queue-profile p1')

        return s1

    def qosQueueProfileCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('do show qos queue-profile')
        assert 'p1' in out

    def qosQueueProfileCommandWithIllegalName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos queue-profile p^%$#1')
        assert 'allowed' in out

    def qosQueueProfileCommandWithNullName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos queue-profile')
        assert 'incomplete' in out

    def qosQueueProfileCommandWithStrictName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos queue-profile strict')
        assert 'cannot' in out

    def qosQueueProfileCommandWithAppliedProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('qos queue-profile default')
        assert 'cannot' in out

    def qosQueueProfileNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('no qos queue-profile p1')
        out = s1.cmdCLI('do show qos queue-profile')
        assert 'p1' not in out

    def qosQueueProfileNoCommandWithIllegalName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos queue-profile p^%$#1')
        assert 'allowed' in out

    def qosQueueProfileNoCommandWithNullName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos queue-profile')
        assert 'incomplete' in out

    def qosQueueProfileNoCommandWithStrictName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos queue-profile strict')
        assert 'cannot' in out

    def qosQueueProfileNoCommandWithAppliedProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos queue-profile default')
        assert 'cannot' in out

    def qosQueueProfileNoCommandWithNonExistentProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('no qos queue-profile NonExistent')
        assert 'does not exist' in out

    def qosQueueProfileNameCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('name queue 1 QueueName')
        out = s1.cmdCLI('do show qos queue-profile p1')
        assert 'QueueName' in out

    def qosQueueProfileNameCommandWithIllegalName(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('name queue 1 Queue^%$#Name')
        assert 'allowed' in out

    def qosQueueProfileNameCommandWithNullName(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('name queue 1')
        assert 'incomplete' in out

    def qosQueueProfileNameCommandWithIllegalQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('name queue 8 QueueName')
        assert 'Unknown command' in out

    def qosQueueProfileNameCommandWithNullQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('name queue QueueName')
        assert 'Unknown command' in out

    def qosQueueProfileNameNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('name queue 1 QueueName')
        s1.cmdCLI('no name queue 1')
        out = s1.cmdCLI('do show qos queue-profile p1')
        assert 'QueueName' not in out

    def qosQueueProfileNameNoCommandWithIllegalQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('no name queue 8')
        assert 'Unknown command' in out

    def qosQueueProfileNameNoCommandWithNullQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('no name queue')
        assert 'incomplete' in out

    def qosQueueProfileNameNoCommandWithMissingQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('no name queue 2')
        assert 'does not have queue_num' in out

    def qosQueueProfileMapCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('map queue 1 local-priority 2')
        out = s1.cmdCLI('do show qos queue-profile p1')
        assert '2' in out

    def qosQueueProfileMapCommandWithIllegalQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('map queue 8 local-priority 2')
        assert 'Unknown command' in out

    def qosQueueProfileMapCommandWithNullQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('map queue local-priority 2')
        assert 'Unknown command' in out

    def qosQueueProfileMapCommandWithIllegalPriority(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('map queue 1 local-priority 8')
        assert 'Unknown command' in out

    def qosQueueProfileMapCommandWithNullPriority(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('map queue 1 local-priority')
        assert 'incomplete' in out

    def qosQueueProfileMapNoCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('map queue 1 local-priority 2')
        s1.cmdCLI('no map queue 1 local-priority 2')
        out = s1.cmdCLI('do show qos queue-profile p1')
        assert '1         2' not in out

    def qosQueueProfileMapNoCommandWithIllegalQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('no map queue 8 local-priority 2')
        assert 'Unknown command' in out

    def qosQueueProfileMapNoCommandWithNullQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('no map queue local-priority 2')
        assert 'Unknown command' in out

    def qosQueueProfileMapNoCommandWithIllegalPriority(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('no map queue 1 local-priority 8')
        assert 'Unknown command' in out

    def qosQueueProfileMapNoCommandWithNullPriority(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('no map queue 1 local-priority')
        assert 'incomplete' in out

    def qosQueueProfileMapNoCommandDeletesSinglePriority(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('map queue 1 local-priority 2')
        s1.cmdCLI('map queue 1 local-priority 3')
        s1.cmdCLI('no map queue 1 local-priority 2')
        out = s1.cmdCLI('do show qos queue-profile p1')
        assert '1         3' in out

    def qosQueueProfileMapNoCommandDeletesAllPriorities(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('map queue 1 local-priority 2')
        s1.cmdCLI('map queue 1 local-priority 3')
        s1.cmdCLI('no map queue 1')
        out = s1.cmdCLI('do show qos queue-profile p1')
        assert '1         2' not in out
        assert '1         3' not in out

    def qosQueueProfileMapNoCommandWithMissingQueue(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        out = s1.cmdCLI('no map queue 2')
        assert 'does not have queue_num' in out

    def qosQueueProfileShowCommand(self):
        s1 = self.setUp()
        s1.cmdCLI('qos queue-profile p1')
        s1.cmdCLI('name queue 1 QueueName')
        out = s1.cmdCLI('do show qos queue-profile p1')
        assert 'QueueName' in out

    def qosQueueProfileShowCommandWithIllegalName(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show qos queue-profile p^%$#1')
        assert 'allowed' in out

    def qosQueueProfileShowCommandShowsAllProfiles(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show qos queue-profile')
        assert 'applied' in out
        assert 'default' in out

    def qosQueueProfileShowCommandFactoryDefault(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show qos queue-profile factory-default')
        assert 'queue_num' in out

    def qosQueueProfileShowCommandWithNonExistentProfile(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show qos queue-profile NonExistent')
        assert 'does not exist' in out

class Test_qos_queue_profile_cli:
    def setup_class(cls):
        Test_qos_queue_profile_cli.test = QosQueueProfileCliTest()

    def teardown_class(cls):
        Test_qos_queue_profile_cli.test.net.stop()

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

    def test_qosQueueProfileCommand(self):
        self.test.qosQueueProfileCommand()
    def test_qosQueueProfileCommandWithIllegalName(self):
        self.test.qosQueueProfileCommandWithIllegalName()
    def test_qosQueueProfileCommandWithNullName(self):
        self.test.qosQueueProfileCommandWithNullName()
    def test_qosQueueProfileCommandWithStrictName(self):
        self.test.qosQueueProfileCommandWithStrictName()
    def test_qosQueueProfileCommandWithAppliedProfile(self):
        self.test.qosQueueProfileCommandWithAppliedProfile()
    def test_qosQueueProfileNoCommandWithIllegalName(self):
        self.test.qosQueueProfileNoCommandWithIllegalName()
    def test_qosQueueProfileNoCommandWithNullName(self):
        self.test.qosQueueProfileNoCommandWithNullName()
    def test_qosQueueProfileNoCommandWithStrictName(self):
        self.test.qosQueueProfileNoCommandWithStrictName()
    def test_qosQueueProfileNoCommandWithAppliedProfile(self):
        self.test.qosQueueProfileNoCommandWithAppliedProfile()
    def test_qosQueueProfileNoCommandWithNonExistentProfile(self):
        self.test.qosQueueProfileNoCommandWithNonExistentProfile()
    def test_qosQueueProfileNameCommand(self):
        self.test.qosQueueProfileNameCommand()
    def test_qosQueueProfileNameCommandWithIllegalName(self):
        self.test.qosQueueProfileNameCommandWithIllegalName()
    def test_qosQueueProfileNameCommandWithNullName(self):
        self.test.qosQueueProfileNameCommandWithNullName()
    def test_qosQueueProfileNameCommandWithIllegalQueue(self):
        self.test.qosQueueProfileNameCommandWithIllegalQueue()
    def test_qosQueueProfileNameCommandWithNullQueue(self):
        self.test.qosQueueProfileNameCommandWithNullQueue()
    def test_qosQueueProfileNameNoCommand(self):
        self.test.qosQueueProfileNameNoCommand()
    def test_qosQueueProfileNameNoCommandWithIllegalQueue(self):
        self.test.qosQueueProfileNameNoCommandWithIllegalQueue()
    def test_qosQueueProfileNameNoCommandWithNullQueue(self):
        self.test.qosQueueProfileNameNoCommandWithNullQueue()
    def test_qosQueueProfileNameNoCommandWithMissingQueue(self):
        self.test.qosQueueProfileNameNoCommandWithMissingQueue()
    def test_qosQueueProfileMapCommand(self):
        self.test.qosQueueProfileMapCommand()
    def test_qosQueueProfileMapCommandWithIllegalQueue(self):
        self.test.qosQueueProfileMapCommandWithIllegalQueue()
    def test_qosQueueProfileMapCommandWithNullQueue(self):
        self.test.qosQueueProfileMapCommandWithNullQueue()
    def test_qosQueueProfileMapCommandWithIllegalPriority(self):
        self.test.qosQueueProfileMapCommandWithIllegalPriority()
    def test_qosQueueProfileMapCommandWithNullPriority(self):
        self.test.qosQueueProfileMapCommandWithNullPriority()
    def test_qosQueueProfileMapNoCommand(self):
        self.test.qosQueueProfileMapNoCommand()
    def test_qosQueueProfileMapNoCommandWithIllegalQueue(self):
        self.test.qosQueueProfileMapNoCommandWithIllegalQueue()
    def test_qosQueueProfileMapNoCommandWithNullQueue(self):
        self.test.qosQueueProfileMapNoCommandWithNullQueue()
    def test_qosQueueProfileMapNoCommandWithIllegalPriority(self):
        self.test.qosQueueProfileMapNoCommandWithIllegalPriority()
    def test_qosQueueProfileMapNoCommandWithNullPriority(self):
        self.test.qosQueueProfileMapNoCommandWithNullPriority()
    def test_qosQueueProfileMapNoCommandDeletesSinglePriority(self):
        self.test.qosQueueProfileMapNoCommandDeletesSinglePriority()
    def test_qosQueueProfileMapNoCommandDeletesAllPriorities(self):
        self.test.qosQueueProfileMapNoCommandDeletesAllPriorities()
    def test_qosQueueProfileMapNoCommandWithMissingQueue(self):
        self.test.qosQueueProfileMapNoCommandWithMissingQueue()
    def test_qosQueueProfileShowCommand(self):
        self.test.qosQueueProfileShowCommand()
    def test_qosQueueProfileShowCommandWithIllegalName(self):
        self.test.qosQueueProfileShowCommandWithIllegalName()
    def test_qosQueueProfileShowCommandShowsAllProfiles(self):
        self.test.qosQueueProfileShowCommandShowsAllProfiles()
    def test_qosQueueProfileShowCommandFactoryDefault(self):
        self.test.qosQueueProfileShowCommandFactoryDefault()
    def test_qosQueueProfileShowCommandWithNonExistentProfile(self):
        self.test.qosQueueProfileShowCommandWithNonExistentProfile()