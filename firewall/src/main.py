#!/usr/bin/env python3

import sys
import os
import argparse
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtGui import QIcon
import signal

# Add project directories to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import project modules
from utils.permissions import PermissionChecker
from utils.notifier import Notifier
from firewall_core.packet_interceptor import PacketInterceptor
from firewall_core.rule_engine import RuleEngine
from firewall_core.rule_manager import RuleManager
from firewall_core.logger import FirewallLogger
from firewall_core.firewall_controller import FirewallController
from gui.main_window import MainWindow

def initialize_components():
    """Initialize the firewall components"""
    # Setup data directories
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    # Initialize the logger
    logs_json = os.path.join(data_dir, 'logs.json')
    firewall_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'firewall.log')
    logger = FirewallLogger(logs_json, python_log_path=firewall_log_path)
    
    # Initialize rule manager
    rules_file = os.path.join(data_dir, 'rules.json')
    rule_manager = RuleManager(rules_file, logger)
    
    # Initialize rule engine with rules
    rule_engine = RuleEngine(logger)
    rules = rule_manager.load_rules()
    rule_engine.load_rules(rules)
    
    # Initialize packet sniffer
    packet_interceptor = PacketInterceptor(rule_engine, logger)
    
    # Initialize firewall controller
    firewall_controller = FirewallController(rule_engine, packet_interceptor, logger)
    
    # Initialize notifier for alerts
    notifier = Notifier()
    
    return {
        'logger': logger,
        'rule_manager': rule_manager,
        'rule_engine': rule_engine,
        'packet_interceptor': packet_interceptor,
        'firewall_controller': firewall_controller,
        'notifier': notifier
    }

def handle_cli_args(components, args):
    """Handle command line arguments"""
    if args.start:
        print("Starting firewall...")
        success = components['firewall_controller'].start()
        if success:
            print("Firewall started successfully.")
            if not args.quiet:
                components['notifier'].notify_firewall_status("Started")
        else:
            print("Failed to start firewall.")
            sys.exit(1)
            
    elif args.stop:
        print("Stopping firewall...")
        success = components['firewall_controller'].stop()
        if success:
            print("Firewall stopped successfully.")
            if not args.quiet:
                components['notifier'].notify_firewall_status("Stopped")
        else:
            print("Failed to stop firewall.")
            sys.exit(1)
            
    elif args.status:
        status = components['firewall_controller'].status()
        print("Firewall Status:")
        for key, value in status.items():
            print(f"  {key}: {value}")

def load_style_sheet():
    """Load the application style sheet"""
    qss_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                          'gui', 'theme.qss')
    try:
        with open(qss_path, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"Failed to load style sheet: {e}")
        return ""

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Python Firewall')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--start', action='store_true', help='Start the firewall')
    group.add_argument('--stop', action='store_true', help='Stop the firewall')
    group.add_argument('--status', action='store_true', help='Show firewall status')
    group.add_argument('--gui', action='store_true', help='Launch the GUI', default=True)
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress notifications')
    args = parser.parse_args()
    
    # Handle Ctrl+C gracefully for CLI mode
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
    
    # Check for admin privileges
    if not PermissionChecker.is_admin():
        print("Warning: This application needs administrator/root privileges.")
        print("Some features may not work correctly.")
        
        if args.start or args.stop:
            print("Error: Admin privileges required to start/stop the firewall.")
            sys.exit(1)
    
    # Initialize components
    components = initialize_components()
    
    # If CLI commands specified, handle them and exit (unless GUI requested)
    if args.start or args.stop or args.status:
        handle_cli_args(components, args)
        if not args.gui:
            sys.exit(0)
    
    # Launch GUI
    app = QApplication(sys.argv)
    app.setApplicationName("Python Firewall")
    
    # Load and apply stylesheet
    app.setStyleSheet(load_style_sheet())
    
    # Create and show the main window
    main_window = MainWindow(
        firewall_controller=components['firewall_controller'],
        rule_manager=components['rule_manager'],
        logger=components['logger']
    )
    main_window.show()
    
    # Set up a hook to handle blocked connections with notifications

    def on_connection_blocked(packet_info):
        src_ip = packet_info.get('src_ip', 'unknown')
        dst_ip = packet_info.get('dst_ip', 'unknown')
        dst_port = packet_info.get('dst_port', 'unknown')
        protocol = packet_info.get('protocol_name', 'unknown')
        components['notifier'].notify_blocked_connection(src_ip, dst_ip, dst_port, protocol)
        main_window.blocked_connection_signal.emit(packet_info)
    # Remove the reference to refresh_logs
    # main_window.log_viewer.refresh_logs()  # This line is causing the error
    # Hook this up to the logger (this would need to be implemented in the logger)
    if hasattr(components['logger'], 'set_block_callback'):
        components['logger'].set_block_callback(on_connection_blocked)
    
    # Start the application event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()