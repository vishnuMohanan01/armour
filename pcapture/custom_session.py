import csv
from collections import defaultdict

from scapy.sessions import DefaultSession

from features.context.packet_direction import PacketDirection
from firewall.sieve import Firewall
from flow import Flow

EXPIRED_UPDATE = 40
MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 100


class CustomSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):

        self.packets_count = 0
        self.clumped_flows_per_label = defaultdict(list)

        super(CustomSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer

        return super(CustomSession, self).toPacketList()

    def on_packet_received(self, packet):
        packet_direction = PacketDirection(packet=packet, sys_ip=self.sys_ip)
        direction = packet_direction.get_direction()

        flow = Flow(packet, direction, packet_direction)
        flow.add_packet(packet, direction)
        packet_info = flow.get_data()

        """Trigger Firewall
        Entry point to CLF Pipeline and 
        IP blacklisting procedures
        """
        firewall = Firewall(clf_model=self.clf_model, packet_info=packet_info)
        firewall.filter()


def generate_session_class(clf_model, sys_ip):
    return type(
        "NewSession",
        (CustomSession,),
        {
            "clf_model": clf_model,
            "sys_ip": sys_ip
        },
    )
