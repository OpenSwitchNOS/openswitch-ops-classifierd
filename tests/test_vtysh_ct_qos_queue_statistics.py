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

class QosQueueStatisticsCliTest(OpsVsiTest):
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

        return s1

    def qosShowQueueStatisticsCommandWithSingleInterface(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show interface 1 queues')
        assert 'Q0' in out
        assert 'Q1' in out
        assert 'Q2' in out
        assert 'Q3' in out
        assert 'Q4' in out
        assert 'Q5' in out
        assert 'Q6' in out
        assert 'Q7' in out

    def qosShowQueueStatisticsCommandWithAllInterfaces(self):
        s1 = self.setUp()
        out = s1.cmdCLI('do show interface queues')
        assert 'Q0' in out
        assert 'Q1' in out
        assert 'Q2' in out
        assert 'Q3' in out
        assert 'Q4' in out
        assert 'Q5' in out
        assert 'Q6' in out
        assert 'Q7' in out

class Test_qos_queue_statistics_cli:
    def setup_class(cls):
        Test_qos_queue_statistics_cli.test = QosQueueStatisticsCliTest()

    def teardown_class(cls):
        Test_qos_queue_statistics_cli.test.net.stop()

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

    def test_qosShowQueueStatisticsCommandWithSingleInterface(self):
        self.test.qosShowQueueStatisticsCommandWithSingleInterface()
    def test_qosShowQueueStatisticsCommandWithAllInterfaces(self):
        self.test.qosShowQueueStatisticsCommandWithAllInterfaces()
