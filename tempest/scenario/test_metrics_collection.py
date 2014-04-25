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

import time

from tempest.common import debug
from tempest import config
from tempest.openstack.common import log as logging
from tempest.scenario import manager
from tempest import test

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestMetricsScenario(manager.OfficialClientTest):

    """
    This test suite verifies that the VM metrics are properly collected
    and have non-zero values. This is done via the ceilometer API.

    setup:
        1. create a basic, bootable glance image
        2. creates a keypair
        3. boots a new VM using the created image and keypair
        4. creates a floating IP
        5. associates the floating IP to the created VM
        6. adds nova security group rules that allow ssh
        7. verifies that the VM was created succesfully by
        connecting to it via ssh
        8. wait an interval of time which represents
        the polling period of the ceilometer agent

    Waiting for the ceilometer agent to poll the resources is crucial,
    otherwise the test suite will fail due to the fact that no samples
    would be found published before checking the samples.

    The ceilometer agent's polling interval should have the same value as
    the test suite's metrics_polling_interval. This can be done in two ways:
        a. Configure tempest's metrics_polling_interval, by adding the
        following line in tempest.conf, in the telemetry section:
        metrics_polling_interval = <desired value>
        b. Set the interval value in pipeline.yaml on the compute node to
        the desired value and restart the ceilometer compute agent.

    The second method is preferred, as the interval value defined in
    pipeline.yaml is 600 seconds, which would mean each test would last
    at least 10 minutes.

    tests:
        1. test_cpu_metrics
        2. test_network_incoming_bytes_metrics
        3. test_network_outgoing_bytes_metrics
        4. test_disk_read_bytes_metrics
        5. test_disk_write_bytes_metrics

    assumptions:
        1. Ceilometer agent on the compute node is running
        2. Ceilometer agent on the compute node has the same polling interval
        defined in pipeline.yaml as metrics_polling_interval defined in this
        test suite.

    """

    def setUp(self):
        super(TestMetricsScenario, self).setUp()
        self.glance_image_create()
        self.nova_keypair_add()
        self.nova_boot()

        self.nova_floating_ip_create()
        self.nova_floating_ip_add()
        self._create_loginable_secgroup_rule_nova()

        self.ssh_to_server()
        time.sleep(CONF.telemetry.metrics_polling_interval)

    def _create_loginable_secgroup_rule_nova(self, client=None,
                                             secgroup_id=None):
        if client is None:
            client = self.compute_client
        rules = super(
            TestMetricsScenario, self)._create_loginable_secgroup_rule_nova(
                client, secgroup_id)

        for rule in rules:
            self.addCleanup(client.security_group_rules.delete, rule)

    def _wait_for_server_status(self, status):
        server_id = self.server.id
        self.status_timeout(
            self.compute_client.servers, server_id, status)

    def nova_keypair_add(self):
        self.keypair = self.create_keypair()

    def nova_boot(self):
        create_kwargs = {'key_name': self.keypair.name}
        self.server = self.create_server(image=self.image,
                                         create_kwargs=create_kwargs)

    def cinder_create(self):
        self.volume = self.create_volume()

    def cinder_list(self):
        volumes = self.volume_client.volumes.list()
        self.assertIn(self.volume, volumes)

    def cinder_show(self):
        volume = self.volume_client.volumes.get(self.volume.id)
        self.assertEqual(self.volume, volume)

    def nova_volume_attach(self):
        attach_vol_client = self.compute_client.volumes.create_server_volume
        volume = attach_vol_client(self.server.id,
                                   self.volume.id,
                                   '/dev/vdb')
        self.assertEqual(self.volume.id, volume.id)
        self.wait_for_volume_status('in-use')

    def nova_floating_ip_create(self):
        self.floating_ip = self.compute_client.floating_ips.create()
        self.addCleanup(self.floating_ip.delete)

    def nova_floating_ip_add(self):
        self.server.add_floating_ip(self.floating_ip)

    def ssh_to_server(self):
        try:
            self.linux_client = self.get_remote_client(self.floating_ip.ip)
            self.linux_client.validate_authentication()
        except Exception:
            LOG.exception('ssh to server failed.')
            self._log_console_output()
            debug.log_net_debug()
            raise

    def check_partitions(self):
        partitions = self.linux_client.get_partitions()
        self.assertEqual(1, partitions.count('vdb'))

    def nova_volume_detach(self):
        detach_vol_client = self.compute_client.volumes.delete_server_volume
        detach_vol_client(self.server.id, self.volume.id)
        self.wait_for_volume_status('available')

        volume = self.volume_client.volumes.get(self.volume.id)
        self.assertEqual('available', volume.status)

    def telemetry_check_samples(self, resource_id, meter_name):
        LOG.info("Checking %(meter_name)s for resource %(resource_id)s" % {
            'meter_name': meter_name, 'resource_id': resource_id})

        samples = self.telemetry_client.samples.list(meter_name)
        self.assertTrue(samples is not None and len(samples) > 0,
                        'Telemetry client returned no samples.')

        expected_samples = [s for s in samples if
                            s.resource_id == resource_id]
        self.assertTrue(len(expected_samples) > 0,
                        'No meter %(meter_name)s samples for resource '
                        '%(resource_id)s found.' % {
                            'meter_name': meter_name,
                            'resource_id': resource_id})

        non_zero_valued_samples = [s for s in expected_samples if
                                   s.counter_volume > 0]
        self.assertTrue(len(non_zero_valued_samples) > 0,
                        'All meter %(meter_name)s samples for resource '
                        '%(resource_id)s are 0.' % {
                            'meter_name': meter_name,
                            'resource_id': resource_id})

    def _get_nova_instance_cpu_resource_id(self):
        return self.server.id

    def _get_nova_instance_disk_resource_id(self):
        return self.server.id

    def _get_nova_instance_port_resource_id(self):
        start_res_id = self.server.id
        resources = self.telemetry_client.resources.list()
        res_ids = [r.resource_id for r in resources
                   if r.resource_id.startswith('instance-') and
                   start_res_id in r.resource_id]

        self.assertEqual(len(res_ids), 1)
        return res_ids[0]

    @test.services('compute', 'image', 'metering')
    def test_cpu_metrics(self):
        cpu_res_id = self._get_nova_instance_cpu_resource_id()
        self.telemetry_check_samples(cpu_res_id, 'cpu')

    @test.services('compute', 'image', 'network', 'metering')
    def test_network_incoming_bytes_metrics(self):
        port_res_id = self._get_nova_instance_port_resource_id()
        self.telemetry_check_samples(port_res_id, 'network.incoming.bytes')

    @test.services('compute', 'image', 'network', 'metering')
    def test_network_outgoing_bytes_metrics(self):
        port_res_id = self._get_nova_instance_port_resource_id()
        self.telemetry_check_samples(port_res_id, 'network.outgoing.bytes')

    @test.services('compute', 'image', 'metering')
    def test_disk_read_bytes_metrics(self):
        disk_resource_id = self._get_nova_instance_disk_resource_id()
        self.telemetry_check_samples(disk_resource_id, 'disk.read.bytes')

    @test.services('compute', 'image', 'metering')
    def test_disk_write_bytes_metrics(self):
        disk_resource_id = self._get_nova_instance_disk_resource_id()
        self.telemetry_check_samples(disk_resource_id, 'disk.write.bytes')
