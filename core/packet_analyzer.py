from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import ipaddress
from utils.logger import logger

class PacketAnalyzer:
    """Network packet analysis and feature extraction"""
    
    def __init__(self):
        self.supported_protocols = ['tcp', 'udp', 'icmp', 'arp']
        logger.info("PacketAnalyzer initialized")
    
    def parse_packet(self, packet):
        """Extract comprehensive information from network packet"""
        try:
            packet_info = {
                'timestamp': datetime.now(),
                'raw_packet': packet,
                'size': len(packet),
                'protocols': []
            }
            
            # Layer 2 - Ethernet
            if packet.haslayer(Ether):
                packet_info['src_mac'] = packet[Ether].src
                packet_info['dst_mac'] = packet[Ether].dst
                packet_info['protocols'].append('ethernet')
            
            # Layer 3 - IP
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info.update({
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'ip_version': ip_layer.version,
                    'ttl': ip_layer.ttl,
                    'protocol': ip_layer.proto,
                    'packet_id': ip_layer.id,
                    'flags': ip_layer.flags,
                    'frag': ip_layer.frag
                })
                packet_info['protocols'].append('ip')
                
                # Check for fragmentation
                if ip_layer.flags.MF or ip_layer.frag > 0:
                    packet_info['fragmented'] = True
                else:
                    packet_info['fragmented'] = False
            
            # Layer 4 - Transport protocols
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'tcp_flags': tcp_layer.flags,
                    'tcp_seq': tcp_layer.seq,
                    'tcp_ack': tcp_layer.ack,
                    'tcp_window': tcp_layer.window,
                    'transport_protocol': 'tcp'
                })
                packet_info['protocols'].append('tcp')
                
                # TCP flag analysis
                packet_info['tcp_flags_str'] = self._get_tcp_flags_string(tcp_layer.flags)
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'udp_length': udp_layer.len,
                    'transport_protocol': 'udp'
                })
                packet_info['protocols'].append('udp')
                
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_info.update({
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code,
                    'transport_protocol': 'icmp'
                })
                packet_info['protocols'].append('icmp')
            
            # ARP packets
            if packet.haslayer(ARP):
                arp_layer = packet[ARP]
                packet_info.update({
                    'arp_op': arp_layer.op,
                    'arp_psrc': arp_layer.psrc,
                    'arp_pdst': arp_layer.pdst,
                    'arp_hwsrc': arp_layer.hwsrc,
                    'arp_hwdst': arp_layer.hwdst,
                    'transport_protocol': 'arp'
                })
                packet_info['protocols'].append('arp')
            
            # Application layer detection
            packet_info['application_protocol'] = self._detect_application_protocol(packet_info)
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error parsing packet: {e}")
            return None
    
    def _get_tcp_flags_string(self, flags):
        """Convert TCP flags to readable string"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        if flags & 0x40: flag_names.append('ECE')
        if flags & 0x80: flag_names.append('CWR')
        return ','.join(flag_names) if flag_names else 'NONE'
    
    def _detect_application_protocol(self, packet_info):
        """Detect application layer protocol based on ports and content"""
        if 'dst_port' not in packet_info:
            return 'unknown'
        
        port = packet_info['dst_port']
        protocol_map = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 67: 'dhcp', 68: 'dhcp',
            69: 'tftp', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            135: 'rpc', 139: 'netbios', 445: 'smb',
            1433: 'mssql', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 6379: 'redis'
        }
        
        return protocol_map.get(port, f'port-{port}')
    
    def is_suspicious_packet(self, packet_info):
        """Basic suspicious packet detection"""
        suspicious_indicators = []
        
        if not packet_info:
            return False, []
        
        # Check for suspicious ports
        suspicious_ports = [135, 139, 445, 1433, 3389, 4444, 5555, 6666, 7777]
        if packet_info.get('dst_port') in suspicious_ports:
            suspicious_indicators.append(f"Suspicious destination port: {packet_info['dst_port']}")
        
        # Check for fragmented packets
        if packet_info.get('fragmented'):
            suspicious_indicators.append("Fragmented packet detected")
        
        # Check for unusual TCP flags
        tcp_flags = packet_info.get('tcp_flags_str', '')
        if tcp_flags in ['FIN', 'NULL', 'SYN,FIN', 'SYN,RST']:
            suspicious_indicators.append(f"Suspicious TCP flags: {tcp_flags}")
        
        # Check for private IP as source from external interface
        src_ip = packet_info.get('src_ip')
        if src_ip:
            try:
                ip = ipaddress.ip_address(src_ip)
                if not ip.is_private and packet_info.get('dst_port', 0) < 1024:
                    suspicious_indicators.append("External IP accessing privileged port")
            except ValueError:
                pass
        
        return len(suspicious_indicators) > 0, suspicious_indicators
    
    def extract_features(self, packet_info):
        """Extract features for machine learning analysis (future enhancement)"""
        features = {
            'packet_size': packet_info.get('size', 0),
            'protocol_score': self._get_protocol_score(packet_info.get('transport_protocol', '')),
            'port_risk_score': self._get_port_risk_score(packet_info.get('dst_port', 0)),
            'flag_risk_score': self._get_flag_risk_score(packet_info.get('tcp_flags_str', '')),
            'fragmentation_score': 1 if packet_info.get('fragmented') else 0,
            'hour_of_day': packet_info.get('timestamp', datetime.now()).hour
        }
        return features
    
    def _get_protocol_score(self, protocol):
        """Assign risk score based on protocol"""
        scores = {'tcp': 0.3, 'udp': 0.2, 'icmp': 0.5, 'arp': 0.1}
        return scores.get(protocol, 0.0)
    
    def _get_port_risk_score(self, port):
        """Assign risk score based on destination port"""
        if port == 0:
            return 0.0
        elif port < 1024:  # Privileged ports
            return 0.7
        elif port in [1433, 3389, 5432, 3306]:  # Database/RDP ports
            return 0.9
        else:
            return 0.1
    
    def _get_flag_risk_score(self, flags):
        """Assign risk score based on TCP flags"""
        high_risk_flags = ['FIN', 'NULL', 'SYN,FIN', 'SYN,RST']
        return 0.9 if flags in high_risk_flags else 0.1

# Test function
def test_packet_analyzer():
    """Test packet analyzer with sample data"""
    analyzer = PacketAnalyzer()
    
    # Create a test packet
    test_packet = IP(src="192.168.1.10", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="S")
    
    # Analyze the packet
    packet_info = analyzer.parse_packet(test_packet)
    
    if packet_info:
        print("Packet Analysis Results:")
        print(f"Source IP: {packet_info.get('src_ip')}")
        print(f"Destination IP: {packet_info.get('dst_ip')}")
        print(f"Source Port: {packet_info.get('src_port')}")
        print(f"Destination Port: {packet_info.get('dst_port')}")
        print(f"Protocol: {packet_info.get('transport_protocol')}")
        print(f"TCP Flags: {packet_info.get('tcp_flags_str')}")
        print(f"Application Protocol: {packet_info.get('application_protocol')}")
        
        is_suspicious, indicators = analyzer.is_suspicious_packet(packet_info)
        print(f"Suspicious: {is_suspicious}")
        if indicators:
            print(f"Indicators: {indicators}")
        
        features = analyzer.extract_features(packet_info)
        print(f"Risk Features: {features}")
    else:
        print("Failed to analyze packet")

if __name__ == "__main__":
    test_packet_analyzer()