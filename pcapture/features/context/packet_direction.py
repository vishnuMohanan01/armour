#!/usr/bin/env python

from enum import Enum, auto


class PacketDirection:
    def __init__(self, packet, sys_dst_ip):
        self.sys_dst_ip = sys_dst_ip
        self.packet = packet

    class Direction(Enum):
        """Packet Direction creates constants for the direction of the packets.

        There are two given directions that the packets can Feature along
        the line. PacketDirection is an enumeration with the values
        forward (1) and reverse (2).
        """

        REVERSE = auto()
        FORWARD = auto()

    def get_direction(self):
        """Return Packet's inbound or outbound direction
        """

        if self.sys_dst_ip == self.packet["IP"].dst:
            return self.Direction.FORWARD
        else:
            return self.Direction.REVERSE

    def get_packet_flow_key(self) -> tuple:
        """Creates a key signature for a packet.

        Summary:
            Creates a key signature for a packet so it can be
            assigned to a flow.

        Args:
            packet: A network packet
            direction: The direction of a packet

        Returns:
            A tuple of the String IPv4 addresses of the destination,
            the source port as an int,
            the time to live value,
            the window size, and
            TCP flags.

        """
        if "TCP" in self.packet:
            protocol = "TCP"
        elif "UDP" in self.packet:
            protocol = "UDP"
        else:
            raise Exception("Only TCP protocols are supported.")

        if self.get_direction() == self.Direction.FORWARD:
            dest_ip = self.packet["IP"].dst
            src_ip = self.packet["IP"].src
            src_port = self.packet[protocol].sport
            dest_port = self.packet[protocol].dport
        else:
            dest_ip = self.packet["IP"].src
            src_ip = self.packet["IP"].dst
            src_port = self.packet[protocol].dport
            dest_port = self.packet[protocol].sport

        return dest_ip, src_ip, src_port, dest_port

