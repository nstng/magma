"""
Copyright 2020 The Magma Authors.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import unittest
import warnings
from concurrent.futures import Future

from lte.protos.mconfig.mconfigs_pb2 import PipelineD
from magma.pipelined.app.ipv6_solicitation import IPV6SolicitationController
from magma.pipelined.bridge_util import BridgeTools
from magma.pipelined.openflow.registers import DIRECTION_REG, Direction
from magma.pipelined.tests.app.start_pipelined import (
    PipelinedController,
    TestSetup,
)
from magma.pipelined.tests.app.table_isolation import (
    RyuDirectTableIsolator,
    RyuForwardFlowArgsBuilder,
)
from magma.pipelined.tests.pipelined_test_util import (
    SnapshotVerifier,
    create_service_manager,
    start_ryu_app_thread,
    stop_ryu_app_thread,
    wait_after_send,
)


class IPV6RouterSolicitation5GTableTest(unittest.TestCase):
    BRIDGE = 'testing_br'
    BRIDGE_IP = '192.168.128.1'
    IFACE = 'testing_br'
    UE_MAC = '5e:cc:cc:b1:49:4b'
    OTHER_MAC = '0a:00:27:00:00:02'

    @classmethod
    def setUpClass(cls, *_):
        """
        Starts the thread which launches ryu apps

        Create a testing bridge, add a port, setup the port interfaces. Then
        launch the ryu apps for testing pipelined. Gets the references
        to apps launched by using futures.
        """
        super(IPV6RouterSolicitation5GTableTest, cls).setUpClass()
        warnings.simplefilter('ignore')
        cls.service_manager = create_service_manager(
            [],
            ['ipv6_solicitation'],
        )
        cls._tbl_num = cls.service_manager.get_table_num(IPV6SolicitationController.APP_NAME)

        ipv6_controller_reference = Future()
        testing_controller_reference = Future()
        test_setup = TestSetup(
            apps=[
                PipelinedController.IPV6RouterSolicitation,
                PipelinedController.Testing,
                PipelinedController.StartupFlows,
            ],
            references={
                PipelinedController.IPV6RouterSolicitation:
                    ipv6_controller_reference,
                PipelinedController.Testing:
                    testing_controller_reference,
                PipelinedController.StartupFlows:
                    Future(),
            },
            config={
                'setup_type': 'LTE',
                'allow_unknown_arps': False,
                'bridge_name': cls.BRIDGE,
                'bridge_ip_address': cls.BRIDGE_IP,
                'ovs_gtp_port_number': 32768,
                'virtual_interface': cls.BRIDGE,
                'local_ue_eth_addr': True,
                'quota_check_ip': '1.2.3.4',
                'ipv6_router_addr': 'd88d:aba4:472f:fc95:7e7d:8457:5301:ebce',
                'clean_restart': True,
                'virtual_mac': 'd6:34:bc:81:5d:40',
                'enable_nat': True,
                'classifier_controller_id': 5,
                'enable5g_features': True,
            },
            mconfig=PipelineD(),
            loop=None,
            service_manager=cls.service_manager,
            integ_test=False,
        )

        BridgeTools.create_bridge(cls.BRIDGE, cls.IFACE)

        cls.thread = start_ryu_app_thread(test_setup)
        cls.solicitation_controller = ipv6_controller_reference.result()
        cls.testing_controller = testing_controller_reference.result()

        cls._prefix_dict = {}
        cls.solicitation_controller._prefix_mapper._prefix_by_interface = \
            cls._prefix_dict

    @classmethod
    def tearDownClass(cls):
        stop_ryu_app_thread(cls.thread)
        BridgeTools.destroy_bridge(cls.BRIDGE)

    def test_ipv6_5g_flows(self):
        """
        Verify that a UPLINK->UE Router Solic & Router Adv
        """

        ulink_args = RyuForwardFlowArgsBuilder(self._tbl_num) \
            .set_eth_match(eth_dst=self.OTHER_MAC, eth_src=self.UE_MAC) \
            .set_reg_value(DIRECTION_REG, Direction.OUT) \
            .build_requests()
        isolator = RyuDirectTableIsolator(ulink_args, self.testing_controller)

        snapshot_verifier = SnapshotVerifier(
            self, self.BRIDGE,
            self.service_manager,
            include_stats=False,
        )

        with isolator, snapshot_verifier:
            wait_after_send(self.testing_controller, wait_time=5)
