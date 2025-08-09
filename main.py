#!/usr/bin/env python3
import sys
import signal
import argparse
import time
import threading
from pathlib import Path
from datetime import datetime

# Add project root to Python path
sys.path.append(str(Path(__file__).parent))

from config.settings import config
from utils.logger import logger
from utils.database import DatabaseManager
from core.packet_analyzer import PacketAnalyzer
from core.firewall import FirewallManager
from core.ids_engine import IDSEngine

# Phase 2 imports
from monitors.traffic_monitor import TrafficMonitor
from monitors.log_monitor import LogMonitor
from monitors.resource_monitor import ResourceMonitor
from detectors.port_scan import PortScanDetector
from detectors.flood_detector import FloodDetector
from detectors.brute_force import BruteForceDetector

# Phase 3 imports
from core.response_framework import ResponseActionFramework
from responses.auto_response import AutoResponseSystem
from responses.manual_review import ManualReviewInterface
from utils.notifier import NotificationManager

class FirewallIDSSystem:
    """Main Firewall and IDS System"""
    
    def __init__(self):
        self.running = False
        self.setup_signal_handlers()
        
        # Core infrastructure
        self.database = None
        self.firewall = None
        self.ids_engine = None
        self.packet_analyzer = None
        
        # Phase 2 components
        self.traffic_monitor = None
        self.log_monitor = None
        self.resource_monitor = None
        self.port_scan_detector = None
        self.flood_detector = None
        self.brute_force_detector = None
        
        # Phase 3 components
        self.response_framework = None
        self.auto_response = None
        self.manual_review = None
        self.notification_manager = None
        
        # Monitoring threads
        self.monitor_threads = []
        
        logger.info("Firewall IDS System initialized")
    
    def setup_signal_handlers(self):
        """Setup graceful shutdown signal handlers"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def initialize_components(self):
        """Initialize all system components"""
        try:
            logger.info("Initializing system components...")
            
            # Initialize core infrastructure
            self.database = DatabaseManager()
            logger.info("✓ Database manager initialized")
            
            self.firewall = FirewallManager()
            logger.info("✓ Firewall manager initialized")
            
            self.ids_engine = IDSEngine()
            logger.info("✓ IDS engine initialized")
            
            self.packet_analyzer = PacketAnalyzer()
            logger.info("✓ Packet analyzer initialized")
            
            # Initialize monitors
            self.traffic_monitor = TrafficMonitor()
            self.log_monitor = LogMonitor()
            self.resource_monitor = ResourceMonitor()
            logger.info("✓ Monitors initialized")
            
            # Initialize detectors
            self.port_scan_detector = PortScanDetector()
            self.flood_detector = FloodDetector()
            self.brute_force_detector = BruteForceDetector()
            logger.info("✓ Detectors initialized")
            
            # Initialize response framework (Phase 3)
            self.response_framework = ResponseActionFramework()
            self.auto_response = self.response_framework.auto_response
            self.manual_review = self.response_framework.manual_review
            self.notification_manager = self.response_framework.notification_manager
            logger.info("✓ Response framework initialized")
            
            # Load rules
            rules = config.get_rules()
            logger.info(f"✓ Loaded {len(rules.get('firewall_rules', []))} firewall rules")
            logger.info(f"✓ Loaded {len(rules.get('ids_rules', []))} IDS rules")
            
            # Check system requirements
            self.check_system_requirements()
            
            logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            return False
    
    def check_system_requirements(self):
        """Check if system meets requirements"""
        import os
        
        # Check if running as root
        if os.geteuid() != 0:
            logger.warning("Not running as root - some features may not work")
        else:
            logger.info("✓ Running with root privileges")
        
        # Check network interfaces
        try:
            import psutil
            interfaces = psutil.net_if_addrs()
            logger.info(f"✓ Available network interfaces: {list(interfaces.keys())}")
            
            if config.NETWORK_INTERFACE not in interfaces:
                logger.warning(f"Configured interface {config.NETWORK_INTERFACE} not found")
        except ImportError:
            logger.warning("psutil not available - cannot check network interfaces")
        
        # Check log files
        log_files = ['/var/log/auth.log', '/var/log/secure', '/var/log/syslog']
        accessible_logs = [f for f in log_files if Path(f).exists()]
        logger.info(f"✓ Accessible log files: {accessible_logs}")
    
    def start_monitoring(self):
        """Start all monitoring systems"""
        logger.info("Starting monitoring systems...")
        self.running = True
        
        try:
            # Start monitors
            self.traffic_monitor.start_monitoring()
            self.log_monitor.start_monitoring()
            self.resource_monitor.start_monitoring()
            logger.info("✓ All monitors started")
            
            # Start response framework
            self.response_framework.start()
            logger.info("✓ Response framework started")
            
            # Start main detection loop
            detection_thread = threading.Thread(target=self._detection_loop, daemon=True)
            detection_thread.start()
            self.monitor_threads.append(detection_thread)
            
            # Start statistics reporting
            stats_thread = threading.Thread(target=self._statistics_loop, daemon=True)
            stats_thread.start()
            self.monitor_threads.append(stats_thread)
            
            logger.info("Detection and statistics threads started")
            
            # Main monitoring loop
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Monitoring interrupted by user")
        except Exception as e:
            logger.error(f"Error in monitoring: {e}")
        finally:
            self.shutdown()
    
    def _detection_loop(self):
        """Main detection processing loop"""
        logger.info("Detection loop started")
        
        try:
            while self.running:
                # Process recent packets from traffic monitor
                if self.traffic_monitor:
                    recent_packets = self.traffic_monitor.get_recent_packets(10)
                    
                    for packet_info in recent_packets:
                        # Run through detectors
                        if packet_info:
                            # Port scan detection
                            port_scan_result = self.port_scan_detector.analyze_packet(packet_info)
                            if port_scan_result:
                                self._handle_detection('port_scan', port_scan_result, packet_info)
                            
                            # Flood detection
                            flood_result = self.flood_detector.analyze_packet(packet_info)
                            if flood_result:
                                self._handle_detection('flood', flood_result, packet_info)
                
                # Process recent log events from log monitor
                if self.log_monitor:
                    recent_events = self.log_monitor.get_recent_events(10)
                    
                    for event in recent_events:
                        # Brute force detection on log events
                        if event.get('line'):
                            brute_force_result = self.brute_force_detector.analyze_log_line(
                                event['line'], 
                                event.get('timestamp')
                            )
                            if brute_force_result:
                                self._handle_detection('brute_force', brute_force_result, event)
                
                # Cleanup old data periodically
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    self._cleanup_detectors()
                
                time.sleep(1)  # Process every second
                
        except Exception as e:
            logger.error(f"Error in detection loop: {e}")
    
    def _statistics_loop(self):
        """Statistics reporting loop"""
        logger.info("Statistics loop started")
        
        try:
            while self.running:
                time.sleep(60)  # Report every minute
                
                if not self.running:
                    break
                
                # Collect statistics
                stats = self._collect_system_statistics()
                
                # Log periodic statistics
                logger.info("=== System Statistics ===")
                logger.info(f"Traffic: {stats['traffic']['packet_count']} packets, "
                          f"{stats['traffic']['packets_per_second']:.1f} pps")
                logger.info(f"Detections: {stats['detections']['port_scans']} port scans, "
                          f"{stats['detections']['floods']} floods, "
                          f"{stats['detections']['brute_force']} brute force")
                logger.info(f"Resources: CPU {stats['resources']['cpu']:.1f}%, "
                          f"Memory {stats['resources']['memory']:.1f}%")
                logger.info(f"Database: {stats['database']['events_count']} events, "
                          f"{stats['database']['alerts_count']} alerts, "
                          f"{stats['database']['db_size_mb']:.1f} MB")
                logger.info(f"Firewall: {stats['firewall']['active_rules']} rules, "
                          f"{stats['firewall']['blocked_ips']} blocked IPs")
                logger.info(f"IDS Engine: {stats['ids_engine']['events_processed']} events processed, "
                          f"{stats['ids_engine']['alerts_generated']} alerts generated")
                if 'responses' in stats:
                    logger.info(f"Response actions: {stats['responses']['total_actions']} total, "
                              f"{stats['responses']['success_rate']:.1%} success rate, "
                              f"{stats['responses']['pending_actions']} pending")
                logger.info("=" * 50)
                
        except Exception as e:
            logger.error(f"Error in statistics loop: {e}")
    
    def _handle_detection(self, detection_type, detection_result, source_data):
        """Handle a security detection by processing through all systems"""
        try:
            # Create standardized event for IDS engine
            event_data = {
                'event_id': f"{detection_type}_{int(time.time())}_{id(detection_result)}",
                'timestamp': detection_result.get('timestamp') or source_data.get('timestamp', datetime.now()),
                'event_type': detection_type,
                'source_ip': detection_result.get('src_ip') or source_data.get('src_ip'),
                'destination_ip': detection_result.get('dst_ip') or source_data.get('dst_ip'),
                'source_port': source_data.get('src_port'),
                'destination_port': source_data.get('dst_port'),
                'protocol': source_data.get('protocol'),
                'severity': detection_result.get('severity', 'medium'),
                'description': detection_result.get('description', f"{detection_type} detected"),
                'payload': source_data.get('payload', ''),
                'raw_data': source_data
            }
            
            # Process through IDS engine for correlation and enrichment
            if self.ids_engine:
                enriched_event = self.ids_engine.process_event(event_data)
                
                # Store in database
                if self.database:
                    self.database.insert_event(enriched_event)
                
                # Check if this requires alert generation
                threat_score = enriched_event.get('threat_score', 0)
                if threat_score > 50:  # High threat score warrants response
                    # Process through response framework
                    if self.response_framework:
                        detection_info = {
                            'type': detection_type,
                            'severity': enriched_event.get('severity', 'medium'),
                            'src_ip': enriched_event.get('source_ip'),
                            'dst_ip': enriched_event.get('destination_ip'),
                            'timestamp': enriched_event.get('timestamp'),
                            'threat_score': threat_score,
                            'details': detection_result,
                            'event_data': enriched_event
                        }
                        
                        detection_id = self.response_framework.process_detection(detection_info)
                        logger.info(f"Processed {detection_type} detection: {detection_id} (threat score: {threat_score})")
                
            else:
                # Fallback to response framework only
                detection_info = {
                    'type': detection_type,
                    'severity': detection_result.get('severity', 'medium'),
                    'src_ip': detection_result.get('src_ip') or source_data.get('src_ip'),
                    'dst_ip': detection_result.get('dst_ip') or source_data.get('dst_ip'),
                    'timestamp': detection_result.get('timestamp') or source_data.get('timestamp', datetime.now()),
                    'details': detection_result,
                    'raw_data': source_data
                }
                
                if self.response_framework:
                    detection_id = self.response_framework.process_detection(detection_info)
                    logger.info(f"Processed {detection_type} detection: {detection_id}")
                else:
                    logger.warning(f"No processing systems available for {detection_type} detection")
                
        except Exception as e:
            logger.error(f"Error handling {detection_type} detection: {e}")
    
    def _cleanup_detectors(self):
        """Clean up old data from detectors"""
        try:
            if self.port_scan_detector:
                self.port_scan_detector.cleanup_old_data()
            if self.flood_detector:
                self.flood_detector.cleanup_old_data()
            if self.brute_force_detector:
                self.brute_force_detector.cleanup_old_data()
            logger.debug("Detector cleanup completed")
        except Exception as e:
            logger.error(f"Error in detector cleanup: {e}")
    
    def _collect_system_statistics(self):
        """Collect comprehensive system statistics"""
        stats = {
            'traffic': {
                'packet_count': 0,
                'packets_per_second': 0.0,
                'bytes_transferred': 0
            },
            'detections': {
                'port_scans': 0,
                'floods': 0,
                'brute_force': 0,
                'total_alerts': 0
            },
            'resources': {
                'cpu': 0.0,
                'memory': 0.0,
                'connections': 0,
                'disk_usage': 0.0
            },
            'database': {
                'events_count': 0,
                'alerts_count': 0,
                'db_size_mb': 0
            },
            'firewall': {
                'active_rules': 0,
                'blocked_ips': 0,
                'allowed_ips': 0
            },
            'ids_engine': {
                'events_processed': 0,
                'alerts_generated': 0,
                'threat_intel_entries': 0
            }
        }
        
        try:
            # Traffic statistics
            if self.traffic_monitor:
                traffic_stats = self.traffic_monitor.get_statistics()
                stats['traffic'].update(traffic_stats)
            
            # Detection statistics
            if self.port_scan_detector:
                stats['detections']['port_scans'] = len(self.port_scan_detector.get_active_scans())
            if self.flood_detector:
                stats['detections']['floods'] = len(self.flood_detector.get_active_floods())
            if self.brute_force_detector:
                stats['detections']['brute_force'] = len(self.brute_force_detector.get_active_attacks())
            
            stats['detections']['total_alerts'] = (
                stats['detections']['port_scans'] + 
                stats['detections']['floods'] + 
                stats['detections']['brute_force']
            )
            
            # Resource statistics
            if self.resource_monitor:
                resource_stats = self.resource_monitor.get_statistics()
                stats['resources'].update(resource_stats)
            
            # Database statistics
            if self.database:
                db_stats = self.database.get_database_stats()
                stats['database'] = {
                    'events_count': db_stats.get('events_count', 0),
                    'alerts_count': db_stats.get('alerts_count', 0),
                    'db_size_mb': db_stats.get('db_size_mb', 0)
                }
            
            # Firewall statistics
            if self.firewall:
                fw_stats = self.firewall.get_firewall_status()
                stats['firewall'] = {
                    'active_rules': fw_stats.get('active_rules', 0),
                    'blocked_ips': fw_stats.get('blocked_ips', 0),
                    'allowed_ips': fw_stats.get('allowed_ips', 0)
                }
            
            # IDS Engine statistics
            if self.ids_engine:
                ids_stats = self.ids_engine.get_statistics()
                stats['ids_engine'] = {
                    'events_processed': ids_stats.get('total_events', 0),
                    'alerts_generated': ids_stats.get('total_alerts', 0),
                    'threat_intel_entries': ids_stats.get('threat_intel_ips', 0)
                }
            
            # Response framework statistics
            if self.response_framework:
                response_stats = self.response_framework.get_action_statistics()
                stats['responses'] = {
                    'total_actions': response_stats.get('total_actions', 0),
                    'successful_actions': response_stats.get('successful_actions', 0),
                    'success_rate': response_stats.get('success_rate', 0),
                    'pending_actions': response_stats.get('pending_actions', 0)
                }
            
        except Exception as e:
            logger.error(f"Error collecting statistics: {e}")
        
        return stats
    
    def shutdown(self):
        """Graceful system shutdown"""
        logger.info("Shutting down Firewall IDS System...")
        self.running = False
        
        try:
            # Stop monitors
            if self.traffic_monitor:
                self.traffic_monitor.stop_monitoring()
            if self.log_monitor:
                self.log_monitor.stop_monitoring()
            if self.resource_monitor:
                self.resource_monitor.stop_monitoring()
            
            # Stop response framework
            if self.response_framework:
                self.response_framework.stop()
            
            # Clean up firewall (optional - save current state)
            if self.firewall:
                self.firewall.cleanup_expired_rules()
                logger.info("Firewall rules cleaned up")
            
            # Update IDS engine baseline
            if self.ids_engine:
                self.ids_engine.update_baseline()
                logger.info("IDS baseline updated")
            
            # Perform database cleanup
            if self.database:
                cleanup_stats = self.database.cleanup_old_data()
                if cleanup_stats:
                    logger.info(f"Database cleanup: {cleanup_stats}")
                self.database.close_connections()
                logger.info("Database connections closed")
            
            # Wait for monitor threads to finish
            for thread in self.monitor_threads:
                if thread.is_alive():
                    thread.join(timeout=5)
            
            logger.info("System shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
    
    def run_tests(self):
        """Run comprehensive system tests"""
        logger.info("Running system tests...")
        
        try:
            # Test configuration
            logger.info("Testing configuration...")
            rules = config.get_rules()
            if rules:
                logger.info("✓ Configuration test passed")
            else:
                logger.error("✗ Configuration test failed")
                return False
            
            # Test packet analyzer
            logger.info("Testing packet analyzer...")
            if self.packet_analyzer:
                from scapy.all import IP, TCP
                test_packet = IP(src="192.168.1.10", dst="192.168.1.1")/TCP(sport=12345, dport=80)
                result = self.packet_analyzer.parse_packet(test_packet)
                if result:
                    logger.info("✓ Packet analyzer test passed")
                else:
                    logger.error("✗ Packet analyzer test failed")
                    return False
            
            # Test monitors
            logger.info("Testing monitors...")
            if self.traffic_monitor and self.log_monitor and self.resource_monitor:
                logger.info("✓ Monitors test passed")
            else:
                logger.error("✗ Monitors test failed")
                return False
            
            # Test detectors
            logger.info("Testing detectors...")
            if self.port_scan_detector and self.flood_detector and self.brute_force_detector:
                # Test port scan detector
                test_packet_info = {
                    'src_ip': '192.168.1.100',
                    'dst_ip': '192.168.1.1',
                    'dst_port': 22,
                    'timestamp': datetime.now()
                }
                self.port_scan_detector.analyze_packet(test_packet_info)
                
                # Test flood detector
                self.flood_detector.analyze_packet(test_packet_info)
                
                # Test brute force detector
                test_log_line = "Failed password for user from 192.168.1.100"
                self.brute_force_detector.analyze_log_line(test_log_line, datetime.now())
                
                logger.info("✓ Detectors test passed")
            else:
                logger.error("✗ Detectors test failed")
                return False
            
            # Test statistics collection
            logger.info("Testing statistics collection...")
            stats = self._collect_system_statistics()
            if stats and all(key in stats for key in ['traffic', 'detections', 'resources']):
                logger.info("✓ Statistics test passed")
            else:
                logger.error("✗ Statistics test failed")
                return False
            
            logger.info("All tests passed!")
            return True
            
        except Exception as e:
            logger.error(f"Test error: {e}")
            return False

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description="Firewall and IDS System")
    parser.add_argument('--test', action='store_true', help='Run system tests')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--monitor-only', action='store_true', help='Run in monitoring mode only')
    
    args = parser.parse_args()
    
    # Override config if command line arguments provided
    if args.interface:
        config.NETWORK_INTERFACE = args.interface
    
    if args.debug:
        config.LOG_LEVEL = 'DEBUG'
        # Reinitialize logger with new level
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize system
    system = FirewallIDSSystem()
    
    if not system.initialize_components():
        logger.error("Failed to initialize system")
        sys.exit(1)
    
    # Run tests if requested
    if args.test:
        if system.run_tests():
            logger.info("All tests passed!")
            sys.exit(0)
        else:
            logger.error("Tests failed!")
            sys.exit(1)
    
    # Start monitoring
    try:
        logger.info("Starting Firewall IDS System...")
        system.start_monitoring()
    except Exception as e:
        logger.error(f"System error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()