import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import sniff, get_if_list
import psutil
from utils.logger import logger
from config.settings import config
from core.packet_analyzer import PacketAnalyzer

class TrafficMonitor:
    """Real-time network traffic monitoring and analysis"""
    
    def __init__(self, interface=None):
        self.interface = interface or config.NETWORK_INTERFACE
        self.running = False
        self.packet_analyzer = PacketAnalyzer()
        self.monitor_thread = None
        
        # Traffic statistics
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = None
        
        # Connection tracking
        self.connections = defaultdict(dict)  # {src_ip: {dst_port: count, timestamp}}
        self.traffic_history = deque(maxlen=1000)  # Keep last 1000 packets
        
        # Rate limiting for logging
        self.last_stats_log = datetime.now()
        self.stats_log_interval = 30  # seconds
        
        logger.info(f"TrafficMonitor initialized for interface: {self.interface}")
    
    def start_monitoring(self):
        """Start traffic monitoring in separate thread"""
        if self.running:
            logger.warning("Traffic monitoring already running")
            return
        
        self.running = True
        self.start_time = datetime.now()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Traffic monitoring started")
    
    def stop_monitoring(self):
        """Stop traffic monitoring"""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        logger.info("Traffic monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop using Scapy"""
        try:
            # Check if interface exists
            available_interfaces = get_if_list()
            if self.interface not in available_interfaces:
                logger.error(f"Interface {self.interface} not found. Available: {available_interfaces}")
                if config.MONITOR_ALL_INTERFACES:
                    logger.info("Monitoring all interfaces")
                    self.interface = None  # Monitor all interfaces
                else:
                    return
            
            logger.info(f"Starting packet capture on interface: {self.interface or 'all'}")
            
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                stop_filter=lambda x: not self.running,
                store=False  # Don't store packets in memory
            )
            
        except PermissionError:
            logger.error("Permission denied - run as root for packet capture")
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        try:
            # Update statistics
            self.packet_count += 1
            self.byte_count += len(packet)
            
            # Analyze packet
            packet_info = self.packet_analyzer.parse_packet(packet)
            if not packet_info:
                return
            
            # Add to traffic history
            self.traffic_history.append(packet_info)
            
            # Update connection tracking
            self._update_connections(packet_info)
            
            # Check for suspicious activity
            is_suspicious, indicators = self.packet_analyzer.is_suspicious_packet(packet_info)
            if is_suspicious:
                logger.security_event("SUSPICIOUS_TRAFFIC", 
                    f"Suspicious packet from {packet_info.get('src_ip', 'unknown')}: {', '.join(indicators)}", 
                    "WARNING")
            
            # Log statistics periodically
            self._log_statistics()
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _update_connections(self, packet_info):
        """Update connection tracking information"""
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        timestamp = packet_info.get('timestamp')
        
        if src_ip and dst_port and timestamp:
            if src_ip not in self.connections:
                self.connections[src_ip] = {}
            
            if dst_port not in self.connections[src_ip]:
                self.connections[src_ip][dst_port] = {
                    'count': 0,
                    'first_seen': timestamp,
                    'last_seen': timestamp
                }
            
            self.connections[src_ip][dst_port]['count'] += 1
            self.connections[src_ip][dst_port]['last_seen'] = timestamp
    
    def _log_statistics(self):
        """Log traffic statistics periodically"""
        now = datetime.now()
        if (now - self.last_stats_log).seconds >= self.stats_log_interval:
            duration = (now - self.start_time).total_seconds() if self.start_time else 1
            pps = self.packet_count / duration  # packets per second
            bps = self.byte_count / duration    # bytes per second
            
            logger.info(f"Traffic Stats: {self.packet_count} packets, "
                       f"{self.byte_count} bytes, {pps:.1f} pps, {bps:.1f} bps")
            
            self.last_stats_log = now
    
    def get_statistics(self):
        """Get current traffic statistics"""
        now = datetime.now()
        duration = (now - self.start_time).total_seconds() if self.start_time else 1
        
        return {
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'duration_seconds': duration,
            'packets_per_second': self.packet_count / duration,
            'bytes_per_second': self.byte_count / duration,
            'connections_tracked': len(self.connections),
            'interface': self.interface,
            'running': self.running
        }
    
    def get_top_connections(self, limit=10):
        """Get top connections by packet count"""
        connection_stats = []
        
        for src_ip, ports in self.connections.items():
            total_packets = sum(port_info['count'] for port_info in ports.values())
            unique_ports = len(ports)
            
            connection_stats.append({
                'src_ip': src_ip,
                'total_packets': total_packets,
                'unique_ports': unique_ports,
                'ports': list(ports.keys())
            })
        
        # Sort by total packets descending
        connection_stats.sort(key=lambda x: x['total_packets'], reverse=True)
        return connection_stats[:limit]
    
    def get_recent_packets(self, limit=50):
        """Get recent packet information"""
        return list(self.traffic_history)[-limit:]
    
    def cleanup_old_connections(self, max_age_minutes=60):
        """Clean up old connection tracking data"""
        cutoff_time = datetime.now() - timedelta(minutes=max_age_minutes)
        cleaned_count = 0
        
        for src_ip in list(self.connections.keys()):
            for dst_port in list(self.connections[src_ip].keys()):
                last_seen = self.connections[src_ip][dst_port]['last_seen']
                if last_seen < cutoff_time:
                    del self.connections[src_ip][dst_port]
                    cleaned_count += 1
            
            # Remove empty source IPs
            if not self.connections[src_ip]:
                del self.connections[src_ip]
        
        if cleaned_count > 0:
            logger.debug(f"Cleaned up {cleaned_count} old connection records")

# Test function
def test_traffic_monitor():
    """Test traffic monitor functionality"""
    monitor = TrafficMonitor()
    
    print("Testing TrafficMonitor...")
    print(f"Interface: {monitor.interface}")
    
    # Test statistics
    stats = monitor.get_statistics()
    print(f"Initial stats: {stats}")
    
    # Start monitoring for a short time
    print("Starting monitoring for 10 seconds...")
    monitor.start_monitoring()
    time.sleep(10)
    monitor.stop_monitoring()
    
    # Get final statistics
    final_stats = monitor.get_statistics()
    print(f"Final stats: {final_stats}")
    
    # Get top connections
    top_connections = monitor.get_top_connections(5)
    print(f"Top connections: {top_connections}")

if __name__ == "__main__":
    test_traffic_monitor()