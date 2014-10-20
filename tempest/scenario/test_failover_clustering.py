# Copyright 2014 Cloudbase Solutions Srl
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

from tempest import config
from tempest.openstack.common import log as logging
from tempest.scenario import test_large_ops
from tempest.scenario import test_minimum_basic
from tempest.scenario import test_network_advanced_server_ops
from tempest.scenario import test_network_basic_server_ops
from tempest.scenario import test_server_advanced_ops
from tempest.scenario import test_server_basic_ops
from tempest.scenario import test_snapshot_pattern
from tempest.scenario import test_stamp_pattern
from tempest.scenario import test_volume_boot_pattern
from tempest import test

CONF = config.CONF

LOG = logging.getLogger(__name__)


class FailoverScenarioTest(manager.ScenarioTest):

    def create_server(self, name=None, image=None, flavor=None,
                      wait_on_boot=True, wait_on_delete=True,
                      create_kwargs=None):
        """Creates VM instance.

        @param image: image from which to create the instance
        @param wait_on_boot: wait for status ACTIVE before continue
        @param wait_on_delete: force synchronous delete on cleanup
        @param create_kwargs: additional details for instance creation
        @return: server dict
        """

        # set the availability_zone.
        if 'availability_zone' not in create_kwargs:
            availability_zone = 'nova:%s' % CONF.failover.failover_node
            create_kwargs['availability_zone'] = availability_zone
        else:
            LOG.error('availability_zone is present in kwargs!')

        # create the server as usual.
        super(FailoverScenarioTest, self).create_server(
            name, image, flavor, True, wait_on_delete, create_kwargs)

        # failover the server by reseting its host.
        # assert that it failovered on a different node.

        self.reset_failover_node()
        self.check_new_server_location()

    def reset_failover_node(self):
        self.host_client.reboot_host(CONF.failover.failover_node)

    def check_new_server_location(self):
        LOG.warning(self.server)
        LOG.warning(dir(server))


class TestFailoverLargeOpsScenario(
        test_large_ops.TestLargeOpsScenario,
        FailoverScenarioTest):
    pass


class TestFailoverMinimumBasicScenario(
        test_minimum_basic.TestMinimumBasicScenario,
        FailoverScenarioTest):
    pass


class TestFailoverNetworkAdvancedServerOps(
        test_network_advanced_server_ops.TestNetworkAdvancedServerOps,
        FailoverScenarioTest):
    pass


class TestFailoverServerAdvancedOps(
        test_server_advanced_ops.TestServerAdvancedOps,
        FailoverScenarioTest):
    pass


class TestFailoverNetworkBasicOps(
        test_network_basic_server_ops.TestNetworkBasicOps,
        FailoverScenarioTest):
    pass


class TestFailoverSnapshotPattern(
        test_snapshot_pattern.TestSnapshotPattern,
        FailoverScenarioTest):
    pass


class TestFailoverStampPattern(
        test_stamp_pattern.TestStampPattern,
        FailoverScenarioTest):
    pass


class TestFailoverVolumeBootPattern(
        test_volume_boot_pattern.TestVolumeBootPattern,
        FailoverScenarioTest):
    pass
