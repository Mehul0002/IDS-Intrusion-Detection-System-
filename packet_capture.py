import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

class PacketCapture:
    """
    Handles network packet capturing using Scapy.
    Runs in a separate thread to avoid blocking the GUI.
    """

    def __init__(self, interface=None, callback=None):
        """
        Initialize the packet capture.

        :param interface: Network interface to sniff on (default: None for all)
        :param callback: Function to call for each captured packet
        """
        self.interface = interface
        self.callback = callback
        self.sniffing = False
        self.thread = None

    def start_capture(self):
        """
        Start packet capturing in a separate thread.
        """
        if not self.sniffing:
            self.sniffing = True
            self.thread = threading.Thread(target=self._sniff_packets)
            self.thread.daemon = True
            self.thread.start()

    def stop_capture(self):
        """
        Stop packet capturing.
        """
        self.sniffing = False
        if self.thread:
            self.thread.join(timeout=1)

    def _sniff_packets(self):
        """
        Internal method to perform sniffing.
        """
        sniff(iface=self.interface, prn=self._process_packet, stop_filter=lambda x: not self.sniffing, store=0)

    def _process_packet(self, packet):
        """
        Process each captured packet and extract relevant information.
        """
        if not self.sniffing:
            return

        packet_info = self._extract_packet_info(packet)
        if self.callback:
            self.callback(packet_info)

    def _extract_packet_info(self, packet):
        """
        Extract timestamp, source IP, dest IP, protocol, ports, length, payload.
        """
        timestamp = datetime.now().strftime('%H:%M:%S')
        src_ip = dst_ip = protocol = src_port = dst_port = length = payload = None

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            protocol = packet[IP].proto

            if TCP in packet:
                protocol = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload = bytes(packet[TCP].payload)
            elif UDP in packet:
                protocol = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload = bytes(packet[UDP].payload)
            elif ICMP in packet:
                protocol = 'ICMP'
                payload = bytes(packet[ICMP].payload)
            else:
                payload = bytes(packet[IP].payload)

        flags = None
        if TCP in packet:
            flags = packet[TCP].flags

        return {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length,
            'payload': payload,
            'flags': flags
        }
