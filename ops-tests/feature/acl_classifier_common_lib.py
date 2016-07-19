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


from re import search, findall
from topology_lib_scapy.library import ScapyThread, send_traffic, sniff_traffic
from time import sleep
import re


"""
Use Case for Library Functions:
    filter_str = (
                    "lambda p: ICMP in p and p[IP].src == '10.0.10.1' "
                    "and p[IP].dst == '10.0.10.2'"
                )

    configure_acl(
                    ops1, 'test', '40', 'permit', 'any', '10.0.10.1',
                    '', '10.0.10.2', '', ''
                )

    apply_acl(ops1, '1', 'test', 'in')

    create_and_verify_traffic(
            topology, hs1, hs2, '10.0.10.1',
            '', '10.0.10.2', '', 'IP/ICMP',
            filter_str, 10, True
            )

    no_acl(ops1, 'test')
"""


def configure_acl(
            switch1, name, seq_num, action, proto, src_ip,
            src_port, dst_ip, dst_port, count_str
        ):
    """
    Configure an ACL with one permit or one deny rule
    """

    if action == "permit":
        with switch1.libs.vtysh.ConfigAccessListIpTestname(name) as ctx:
            ctx.permit(
                      '',
                      seq_num, proto, src_ip, src_port,
                      dst_ip, dst_port, count_str
                      )

    elif action == "deny":
        with switch1.libs.vtysh.ConfigAccessListIpTestname(name) as ctx:
            ctx.deny(
                      '',
                      seq_num, proto, src_ip, src_port,
                      dst_ip, dst_port, count_str
                      )
    else:
        assert(False)

    action_line_str = (
                        seq_num + ' ' + action + ' ' + proto
                        + ' ' + src_ip + ' ' + src_port +
                        ' ' + dst_ip + ' ' + dst_port +
                        ' ' + count_str
                    )
    action_line_str = re.sub('\s+', ' ', action_line_str).strip()

    action_line_re = re.compile(action_line_str)

    test_result = switch1('show run')
    assert re.search(action_line_re, test_result)


def apply_acl(switch1, port_num, acl_name, direction):
    """
    Apply ACL on interface in ingress or egress direction
    """

    if direction == 'in':
        with switch1.libs.vtysh.ConfigInterface(port_num) as ctx:
            ctx.apply_access_list_ip_in(acl_name)
    elif direction == 'out':
        with switch1.libs.vtysh.ConfigInterface(port_num) as ctx:
            ctx.apply_access_list_ip_out(acl_name)
    else:
        assert(False)

    apply_line_re = re.compile(
                        'apply access-list ip '
                        + acl_name + '\s+' + direction
                    )

    test_result = switch1('show run')
    assert re.search(apply_line_re, test_result)


def no_acl(switch1, acl_name):
    """
    Remove an ACL
    """

    with switch1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip(acl_name)

    test_result = switch1('show run')
    assert search(r'(?!access-list\s+ip\s+{})'.format(acl_name), test_result)


def create_and_verify_traffic(
                        topology, tx_host, rx_host, src_ip,
                        src_port, dst_ip, dst_port, proto_str,
                        filter_str, tx_count, rx_expect
                        ):
    ip_packet = tx_host.libs.scapy.ip(
                            "dst='" + dst_ip + "', src='" +
                            src_ip + "'"
                                       )
    icmp_packet = tx_host.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    port_str = '1'
    timeout = 25

    txthread = ScapyThread(
                send_traffic,
                tx_host.identifier, topology, proto_str, list1, '', tx_count,
                '', 0)

    rxthread = ScapyThread(
                sniff_traffic,
                rx_host.identifier, topology, '', [], filter_str, tx_count,
                port_str, timeout)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)

        assert (rx_expect == (list_result[2] == str(tx_count)))


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
            'Interface {}:{} never brought-up after '
            'waiting for {} seconds'.format(
                switch.identifier, portlbl, timeout
            )
        )
