from datetime import datetime, timedelta

class PortScanDetector:
    """
    Detects port scanning by monitoring SYN packets.
    Alerts if one IP sends SYN to many ports in a short time.
    """

    def __init__(self, alert_callback=None, threshold=10, window_seconds=5):
        """
        Initialize the detector.

        :param alert_callback: Function to call when alert is raised
        :param threshold: Number of ports to trigger alert
        :param window_seconds: Time window in seconds
        """
        self.alert_callback = alert_callback
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.ip_data = {}  # ip: list of (timestamp, port)

    def process_packet(self, packet_info):
        """
        Process a packet for port scan detection.
        Only considers TCP SYN packets.
        """
        if packet_info['protocol'] != 'TCP':
            return

        flags = packet_info.get('flags')
        if flags is None or not (flags & 0x02):  # SYN flag
            return

        src_ip = packet_info['src_ip']
        dst_port = packet_info['dst_port']

        now = datetime.now()

        if src_ip not in self.ip_data:
            self.ip_data[src_ip] = []

        # Add current packet
        self.ip_data[src_ip].append((now, dst_port))

        # Remove old entries
        self.ip_data[src_ip] = [(t, p) for t, p in self.ip_data[src_ip] if now - t < self.window]

        # Check unique ports
        unique_ports = set(p for t, p in self.ip_data[src_ip])
        if len(unique_ports) >= self.threshold:
            alert = {
                'timestamp': packet_info['timestamp'],
                'type': 'Port Scan Detected',
                'src_ip': src_ip,
                'details': f'Scanned {len(unique_ports)} ports in {self.window.seconds} seconds'
            }
            if self.alert_callback:
                self.alert_callback(alert)
            # Reset to avoid repeated alerts
            self.ip_data[src_ip] = []
