# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

from .acl_classifier_common_lib import configure_acl
from .acl_classifier_common_lib import apply_acl
from .acl_classifier_common_lib import no_acl
from .acl_classifier_common_lib import create_and_verify_traffic

filter_udp = "lambda p: UDP in p and p[UDP].dport == 48621 and " \
    "p[IP].src == '1.1.1.1' and p[IP].dst == '1.1.1.2'"
filter_icmp = "lambda p: ICMP in p and p[IP].src == '1.1.1.1' " \
    " and p[IP].dst == '1.1.1.2'"
count = 10


class CommonTestSuite:

    def __init__(self):
        self._aclAddrType = 'null'
        self._aclApp = None
        self._aclDir = None
        self._topo = None
        self._sw1 = None
        self._hs1 = None
        self._hs2 = None

    def set_acl_addr_type(self, addr_type):
        # In the future, the address type will include more address types
        #     valid_args = ('mac', 'ip', 'ipv6')
        valid_args = ('ip')
        assert addr_type in valid_args
        self._aclAddrType = addr_type

    def set_acl_app_type(self, app):
        # In the future, we will be able to specifiy more applications of ACLs
        #     valid_args = ('port', 'vlan', 'tunnel')
        valid_args = ('port')
        assert app in valid_args
        self._aclApp = app

    def set_acl_direction(self, direction):
        valid_args = ('in', 'out')
        assert direction in valid_args
        self._aclDir = direction

    def set_topology(self, topology):
        # valid_args = ('1switch_2host', '2switch_2host', '2switch_2host_lag')
        # TODO: Find a better check then just None
        assert topology is not None
        self._topo = topology

    def set_switch_1(self, switch):
        # TODO: Find a better check then just None
        assert switch is not None
        self._sw1 = switch

    def set_host_1(self, host):
        # TODO: Find a better check then just None
        assert host is not None
        self._hs1 = host

    def set_host_2(self, host):
        # TODO: Find a better check then just None
        assert host is not None
        self._hs2 = host

    def _create_and_verify_udp_traffic(self, rx_expect):
        global filter_udp, count

        tx_host = self._hs1
        rx_host = self._hs2
        src_ip = '1.1.1.1'
        dst_ip = '1.1.1.2'
        src_port = '48620'
        dst_port = '48621'
        proto_str = 'IP/UDP'
        filter_str = filter_udp
        tx_count = count
        create_and_verify_traffic(
                        self._topo, tx_host, rx_host, src_ip,
                        src_port, dst_ip, dst_port, proto_str,
                        filter_str, tx_count, rx_expect
                        )

    def _create_and_verify_icmp_traffic(self, rx_expect):
        global filter_icmp, count

        tx_host = self._hs1
        rx_host = self._hs2
        src_ip = '1.1.1.1'
        dst_ip = '1.1.1.2'
        src_port = ''
        dst_port = ''
        proto_str = 'IP/ICMP'
        filter_str = filter_icmp
        tx_count = count
        create_and_verify_traffic(
                        self._topo, tx_host, rx_host, src_ip,
                        src_port, dst_ip, dst_port, proto_str,
                        filter_str, tx_count, rx_expect
                        )

    def acl_action_udp_any_any(self, step, step_num, action_str):
        # Check for just the private member variables that absolutely have to
        # be defined for this specific test
        assert self._aclApp is not None
        assert self._aclDir is not None
        assert self._topo is not None
        assert self._sw1 is not None
        assert self._hs1 is not None
        assert self._hs2 is not None

        assert isinstance(step_num, int)
        assert isinstance(action_str, str) and \
            action_str in ('permit', 'deny')

        acl_name = 'test'

        step(str(step_num) +
             '.a Configure an ACL with 1 %s udp any any rule'
             % (action_str))

        seq_num = '1'
        action = action_str
        proto = 'udp'
        src_ip = 'any'
        src_port = ''
        dst_ip = 'any'
        dst_port = ''
        count_str = ''
        configure_acl(
            self._sw1, acl_name, seq_num, action, proto, src_ip,
            src_port, dst_ip, dst_port, count_str
        )

        port_num = '1'
        apply_acl(self._sw1, port_num, acl_name, self._aclDir)

        step(str(step_num) + '.b Create and verify UDP packets')
        rx_expect = True if action_str == 'permit' else False
        self._create_and_verify_udp_traffic(rx_expect)

        step(str(step_num) + '.c Remove the configured ACL')
        no_acl(self._sw1, acl_name)

    def acl_action_udp_hs1_hs2(self, step, step_num, action_str):
        # Check for just the private member variables that absolutely have to
        # be defined for this specific test
        assert self._aclApp is not None
        assert self._aclDir is not None
        assert self._topo is not None
        assert self._sw1 is not None
        assert self._hs1 is not None
        assert self._hs2 is not None

        assert isinstance(step_num, int)
        assert isinstance(action_str, str) and \
            action_str in ('permit', 'deny')

        acl_name = 'test'

        step(str(step_num) +
             '.a Configure an ACL with 1 %s udp 1.1.1.1 1.1.1.2 rule'
             % (action_str))

        seq_num = '1'
        action = action_str
        proto = 'udp'
        src_ip = '1.1.1.1'
        src_port = ''
        dst_ip = '1.1.1.2'
        dst_port = ''
        count_str = ''
        configure_acl(
            self._sw1, acl_name, seq_num, action, proto, src_ip,
            src_port, dst_ip, dst_port, count_str
        )

        port_num = '1'
        apply_acl(self._sw1, port_num, acl_name, self._aclDir)

        step(str(step_num) + '.b Create and verify UDP packets')
        rx_expect = True if action_str == 'permit' else False
        self._create_and_verify_udp_traffic(rx_expect)

        step(str(step_num) + '.c Create and verify ICMP packets')
        rx_expect = False
        self._create_and_verify_icmp_traffic(rx_expect)

        step(str(step_num) + '.d Remove the configured ACL')
        no_acl(self._sw1, acl_name)

    def acl_action_udp_prefix_len_mask(self, step, step_num, action_str):
        # Check for just the private member variables that absolutely have to
        # be defined for this specific test
        assert self._aclApp is not None
        assert self._aclDir is not None
        assert self._topo is not None
        assert self._sw1 is not None
        assert self._hs1 is not None
        assert self._hs2 is not None

        assert isinstance(step_num, int)
        assert isinstance(action_str, str) and \
            action_str in ('permit', 'deny')

        acl_name = 'test'

        step(str(step_num) +
             '.a Configure an ACL with 1 %s udp 1.1.1.0/31 1.1.1.0/30 rule'
             % (action_str))

        seq_num = '1'
        action = action_str
        proto = 'udp'
        src_ip = '1.1.1.0/31'
        src_port = ''
        dst_ip = '1.1.1.0/30'
        dst_port = ''
        count_str = ''
        configure_acl(
            self._sw1, acl_name, seq_num, action, proto, src_ip,
            src_port, dst_ip, dst_port, count_str
        )

        port_num = '1'
        apply_acl(self._sw1, port_num, acl_name, self._aclDir)

        step(str(step_num) + '.b Create and verify UDP packets')
        rx_expect = True if action_str == 'permit' else False
        self._create_and_verify_udp_traffic(rx_expect)

        step(str(step_num) + '.c Create and verify ICMP packets')
        rx_expect = False
        self._create_and_verify_icmp_traffic(rx_expect)

        step(str(step_num) + '.d Remove the configured ACL')
        no_acl(self._sw1, acl_name)
