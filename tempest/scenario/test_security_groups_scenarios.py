# Copyright 2014 Cloudbase Solutions
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import socket

from tempest import config
from tempest.openstack.common import log as logging
from tempest.scenario import test_security_groups_basic_ops as test_sg_bops

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestSecurityGroupsAdvancedOps(test_sg_bops.TestSecurityGroupsBase):
    """

    tests:
        1. test_in_tenant_allow
        2. test_in_tenant_allow_deny
        3. test_out_tenant_allow
        4. test_out_tenant_allow_deny
        5. test_in_allow_tcp_port
        6. test_in_allow_udp_port
        7. test_in_allow_tcp_port_range
        8. test_in_allow_udp_port_range


    """

    @classmethod
    def _create_socket_connection(cls, server, port, protocol):
        """ Creates a socket connection to the specified server. """
        if protocol is 'tcp':
            protocol = socket.SOCK_STREAM
        elif protocol is 'udp':
            protocol = socket.SOCK_DGRAM
        else:
            raise Exception('Wrong protocol, dummy!')

        sock = socket.socket(socket.AF_INET, protocol)
        sock.connect((server, port))

        return sock

    def _add_security_group_rule(self, port_range=[''], protocol='icmp',
                                 direction='ingress', remote_address=''):
        """ Creates a security group rule. """
        ruleset = dict(
            protocol=protocol,
            remote_group_id=self.primary_tenant.security_groups['default'].id,
            direction=direction,
            port_range_min=port_range[0],
            port_range_max=port_range[-1],
            remote_ip_prefix=remote_address,
        )

        rule = self._create_security_group_rule(
            secgroup=self.primary_tenant.security_groups['default'],
            **ruleset
        )

        return rule

    def _send_data_through_socket(self, tenant, port, protocol, data):
        """ Sends data to tenant through a socket. """
        dest_ip = self.floating_ips[tenant.access_point].floating_ip_address
        conn = self._create_socket_connection(dest_ip, port, protocol)
        conn.sendall(data + '\n')
        conn.sendall()
        conn.close()

    def _send_data_through_remote_nc(self, tenant, port, protocol, data):
        """ Sends data to tenant server through another server. """
        source_ip = self._get_server_ip(self.primary_tenant.servers[-1])
        destination_ip = self._get_server_ip(self.primary_tenant.servers[0])

        # first, send the ssh key.
        command = 'echo %s > id_rsa' % self.primary_tenant.keypair.private_key
        self._remote_execute(tenant, command)

        # use the tenant's access point to ssh to the second server.
        # send data through nc from the second server to the first server.
        command = ('ssh cirros@%(source_ip)s -i id_rsa '
                   '"echo %(data)s | nc %(destination_ip)s -p %(port)s"' % {
                       'source_ip': source_ip,
                       'data': data,
                       'destination_ip': destination_ip,
                       'port': port})

        self._remote_execute(tenant, command)

    def _remote_execute(self, tenant, command):
        access_point_ssh = self._connect_to_access_point(tenant)
        return access_point_ssh.exec_command(command)

    def _remote_iptables(self, tenant, port, protocol):
        command = ('iptables -A INPUT -p %(protocol)s '
                   '--dport %(port)s -j ACCEPT' % {'protocol': protocol,
                                                   'port': port})
        self._remote_execute(tenant, command)

    def _remote_start_nc(self, tenant, port):
        """
        cirros' nc does not support udp protocol.
        It can only listen and send data through tcp protocol.
        The command will start nc for 5 seconds only and output is send to
        net.listen file, which will be later read to verify the data sent.
        """
        command = 'nc -w 5 -l -p %(port)s & >> net.listen' % {'port': port}
        self._remote_execute(tenant, command)

    def _remote_get_file_content(self, tenant, filename):
        """ Retrieve a file from the tenant. """
        command = 'cat %(filename)s' % {'filename': filename}
        return self._remote_execute(tenant, command)

    def _port_send(self, port_range, protocol, send_data_method):
        """
        Send messages for each port in the range and retrieve the messages
        that are captured.
        """
        for port in range(port_range[0], port_range[-1]):
            self._remote_start_nc(self.primary_tenant, port)
            message = 'Message sent through port %d' % port
            send_data_method(self.primary_tenant, port, protocol, message)

        file_content = self._remote_get_file_content(self.primary_tenant,
                                                     'net.listen')
        lines = file_content.split('\n')
        return lines

    def _test_security_group_scenario(self, port_range, protocol,
                                      direction='ingress', num=1,
                                      send_data_method=None):
        """
        Tests a specific security group scenario, given a certain port range,
        protocol and direction.
        First, it will test wether sending data is possible by default.
        Secondly, it tests wether it is possible after the coresponding
        security group rule has been added.
        Lastly, it removes the created rule and tries sending data once again.
        """
        if not send_data_method:
            send_data_method = self._send_data_through_socket
        msg_port_range = port_range if port_range else [9001, 9010]

        try:
            self._create_tenant_servers(self.primary_tenant, num=num)

            # Test if sending data through the ports is possible by default.
            data = self._port_send(msg_port_range, protocol, send_data_method)
            self.assertEqual([], data, 'Data can be sent through the ports '
                             'as default. Data succesfully sent: %r' % data)

            # Create security group rule that will allow data to be sent
            # through the ports.
            rule = self._add_security_group_rule(port_range=port_range,
                                                 protocol=protocol,
                                                 direction=direction)
            messages = ['Message sent through port %d' % port for port in
                        range(msg_port_range[0], msg_port_range[-1])]

            # Verify that all the data gets through as expected.
            data = self._port_send(msg_port_range, protocol, send_data_method)
            self.assertEqual(messages, data, 'Data could not be sent through '
                             'the ports as expected.')

            # Delete the previously created security group rule and try again.
            rule.delete()
            data = self._port_send(port_range, protocol, send_data_method)
            self.assertEqual([], data)

            self.assertEqual(messages, data, 'Data can be sent through the '
                             'ports without the security group rule. Data '
                             'succesfully sent: %r' % data)

        except Exception:
            self._log_console_output(servers=self.primary_tenant.servers)
            raise

    def _test_security_group_egress(self, port_range, protocol):
        """ Add the ingress security group rule, as we test egress rules. """
        rule = self._add_security_group_rule(port_range=port_range,
                                             protocol=protocol,
                                             direction='ingress')
        self.addCleanup(self.cleanup_wrapper, rule)

        self._test_security_group_scenario([], protocol, 'egress', 2,
                                           self._send_data_through_remote_nc)

    def test_in_allow_tcp_port(self):
        self._test_security_group_scenario([9001], 'tcp')

    def test_in_allow_udp_port(self):
        self._test_security_group_scenario([9001], 'udp')

    def test_in_allow_tcp_port_range(self):
        self._test_security_group_scenario([9001, 9010], 'tcp')

    def test_in_allow_udp_port_range(self):
        self._test_security_group_scenario([9001, 9010], 'udp')

    def test_out_allow_tcp_port(self):
        self._test_security_group_egress([9001, 9010], 'tcp')
