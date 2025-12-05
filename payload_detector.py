class PayloadDetector:
    """
    Detects suspicious payloads by searching for malicious patterns.
    """

    def __init__(self, alert_callback=None):
        """
        Initialize the detector.

        :param alert_callback: Function to call when alert is raised
        """
        self.alert_callback = alert_callback
        self.malicious_patterns = [
            b'malware',
            b'attack',
            b'shellcode',
            b'exploit',
            b'virus',
            b'trojan'
        ]

    def process_packet(self, packet_info):
        """
        Process a packet for payload detection.
        """
        payload = packet_info.get('payload')
        if payload:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            for pattern in self.malicious_patterns:
                if pattern in payload.lower():
                    alert = {
                        'timestamp': packet_info['timestamp'],
                        'type': 'Suspicious Payload Detected',
                        'src_ip': packet_info['src_ip'],
                        'details': f'Pattern "{pattern.decode()}" found in payload'
                    }
                    if self.alert_callback:
                        self.alert_callback(alert)
                    break  # Alert once per packet
