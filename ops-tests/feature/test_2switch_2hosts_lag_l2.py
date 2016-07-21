# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
OpenSwitch Test for simple ping test between two host with LAG interface
"""

from . import constants
from .functions import topology_2switch_2host_lag
from .functions import config_switch_lag_l2
from .functions import config_hosts_l2
from .functions import ping_test_l2
from time import sleep
# from ipdb import set_trace

TOPOLOGY = constants.topology_2switch_2host_lag


def test_2switch_2host_lag_l2(topology):

    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    topology_2switch_2host_lag(ops1, ops2, hs1, hs2)
    config_switch_lag_l2(ops1, ops2)
    config_hosts_l2(hs1, hs2)
    # Wait until interfaces are up
    for switch, portlbl in [(ops1, '1'), (ops1, '5'), (ops1, '6')]:
        wait_until_interface_up(switch, portlbl)
    for switch, portlbl in [(ops2, '1'), (ops2, '5'), (ops2, '6')]:
        wait_until_interface_up(switch, portlbl)

    ping_test_l2(hs1)
    ops1('show run')
    ops2('show run')


def wait_until_interface_up(switch, portlbl, timeout=30, polling_frequency=1):
    """
    Wait until the interface, as mapped by the given portlbl, is marked as up.

    :param switch: The switch node.
    :param str portlbl: Port label that is mapped to the interfaces.
    :param int timeout: Number of seconds to wait.
    :param int polling_frequency: Frequency of the polling.
    :return: None if interface is brought-up. If not, an assertion is raised.
    """
    for i in range(timeout):
            status = switch.libs.vtysh.show_interface(portlbl)
            if status['interface_state'] == 'up':
                break
            sleep(polling_frequency)
    else:
        assert False, (
            'Interface {}:{} never brought-up after'
            'waiting for {} seconds'.format(
                switch.identifier, portlbl, timeout
                )
            )
