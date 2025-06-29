import sys
import os
from PyQt5.QtWidgets import (QMainWindow, QApplication, QTabWidget, QPushButton, 
                            QLabel, QVBoxLayout, QHBoxLayout, QWidget, QFrame,
                            QSplitter, QMessageBox, QStatusBar, QAction, QMenu)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QSize
from PyQt5.QtGui import QIcon, QPixmap, QFont

from gui.rules_editor import RulesEditorWidget
from gui.log_viewer import LogViewerWidget
from gui.alerts_popup import AlertPopup
from utils.permissions import PermissionChecker
from utils.network_utils import NetworkUtils

class FirewallStatusWidget(QFrame):
    """Widget displaying firewall status and controls"""
    toggled = pyqtSignal(bool)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self._running = False
        self._initUI()
        
    def _initUI(self):
        # Main layout
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Firewall Status")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)
        
        # Status indicator
        self.status_label = QLabel("INACTIVE")
        self.status_label.setFont(QFont("Arial", 18, QFont.Bold))
        self.status_label.setStyleSheet("color: red")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Toggle button
        self.toggle_btn = QPushButton("Enable Firewall")
        self.toggle_btn.setFixedHeight(40)
        self.toggle_btn.clicked.connect(self._toggle_firewall)
        layout.addWidget(self.toggle_btn)
        
        # Network stats
        self.stats_widget = QWidget()
        stats_layout = QVBoxLayout()
        
        # Active connections
        self.conn_label = QLabel("Active Connections: 0")
        stats_layout.addWidget(self.conn_label)
        
        # Packets processed
        self.packets_label = QLabel("Packets Processed: 0")
        stats_layout.addWidget(self.packets_label)
        
        # Packets blocked
        self.blocked_label = QLabel("Packets Blocked: 0")
        stats_layout.addWidget(self.blocked_label)
        
        self.stats_widget.setLayout(stats_layout)
        layout.addWidget(self.stats_widget)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
        self.setLayout(layout)
        
    def _toggle_firewall(self):
        """Toggle firewall state"""
        self._running = not self._running
        self.update_status(self._running)
        self.toggled.emit(self._running)
        
    def update_status(self, running):
        """Update the UI to reflect firewall status"""
        self._running = running
        
        if running:
            self.status_label.setText("ACTIVE")
            self.status_label.setStyleSheet("color: green")
            self.toggle_btn.setText("Disable Firewall")
        else:
            self.status_label.setText("INACTIVE")
            self.status_label.setStyleSheet("color: red")
            self.toggle_btn.setText("Enable Firewall")
            
    def update_stats(self, active_connections=0, packets_processed=0, packets_blocked=0):
        """Update the network statistics display"""
        self.conn_label.setText(f"Active Connections: {active_connections}")
        self.packets_label.setText(f"Packets Processed: {packets_processed}")
        self.blocked_label.setText(f"Packets Blocked: {packets_blocked}")

class MainWindow(QMainWindow):
    """Main application window"""
    blocked_connection_signal = pyqtSignal(dict)  # <-- Add this line

    def __init__(self, firewall_controller=None, rule_manager=None, logger=None):
        super().__init__()
        self.firewall_controller = firewall_controller
        self.rule_manager = rule_manager
        self.logger = logger
        self.networks_utils = NetworkUtils()
        self.alert_popup = None
        self.blocked_connection_signal.connect(self._show_blocked_alert)

        self._initUI()
        self._setup_timers()
        self._check_permissions()
        
        
    def _initUI(self):
        """Initialize the user interface"""
        self.setWindowTitle("Firewall Management")
        self.setGeometry(100, 100, 1000, 600)
        
        # Create central widget and layout
        central_widget = QWidget()
        main_layout = QHBoxLayout()
        
        # Left side - Status panel
        self.status_widget = FirewallStatusWidget()
        self.status_widget.toggled.connect(self._toggle_firewall_controller)
        main_layout.addWidget(self.status_widget, 1)
        
        # Right side - Tabbed content
        tab_widget = QTabWidget()
        
        # Rules editor tab
        self.rules_editor = RulesEditorWidget(self.rule_manager)
        tab_widget.addTab(self.rules_editor, "Firewall Rules")
        
        # Log viewer tab
        self.log_viewer = LogViewerWidget(self.logger)
        tab_widget.addTab(self.log_viewer, "Activity Logs")
        
        main_layout.addWidget(tab_widget, 3)
        
        # Set the central widget
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        
        # Create status bar
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)
        
        # Add network info to status bar
        self.net_info_label = QLabel()
        status_bar.addPermanentWidget(self.net_info_label)
        self.update_network_info()
        
        # Create menu bar
        self._setup_menu()

    def _show_blocked_alert(self, packet_info):
        pass
    def _setup_menu(self):
        """Set up the application menu"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        # Exit action
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Firewall menu
        fw_menu = menubar.addMenu('Firewall')
        
        # Start action
        start_action = QAction('Start', self)
        start_action.triggered.connect(lambda: self._toggle_firewall_controller(True))
        fw_menu.addAction(start_action)
        
        # Stop action
        stop_action = QAction('Stop', self)
        stop_action.triggered.connect(lambda: self._toggle_firewall_controller(False))
        fw_menu.addAction(stop_action)
        
        fw_menu.addSeparator()
        
        # Reload rules action
        reload_action = QAction('Reload Rules', self)
        reload_action.triggered.connect(self._reload_rules)
        fw_menu.addAction(reload_action)
        
    def _check_permissions(self):
        """Check if app has admin/root permissions"""
        if not PermissionChecker.is_admin():
            QMessageBox.warning(self, "Permission Warning", 
                              "This application needs administrator/root privileges to function properly.")
            
    def _toggle_firewall_controller(self, enable):
        """Start or stop the firewall controller"""
        if self.firewall_controller:
            if enable:
                success = self.firewall_controller.start()
                if success:
                    self.status_widget.update_status(True)
                    self.statusBar().showMessage("Firewall started", 3000)
                else:
                    QMessageBox.critical(self, "Error", "Failed to start firewall")
            else:
                success = self.firewall_controller.stop()
                if success:
                    self.status_widget.update_status(False)
                    self.statusBar().showMessage("Firewall stopped", 3000)
                else:
                    QMessageBox.critical(self, "Error", "Failed to stop firewall")
        else:
            QMessageBox.warning(self, "Not Initialized", "Firewall controller not initialized")
            
    def _reload_rules(self):
        """Reload the firewall rules"""
        if self.rule_manager and self.firewall_controller:
            # Reload rules from file
            rules = self.rule_manager.load_rules()
            
            # Update rule engine with new rules
            if hasattr(self.firewall_controller, 'rule_engine'):
                self.firewall_controller.rule_engine.load_rules(rules)
                
                # Refresh the rules display
                self.rules_editor.load_rules()
                
                self.statusBar().showMessage("Rules reloaded", 3000)
            
    def _setup_timers(self):
        """Set up periodic timers for updates"""
        # Timer for statistics update (every 5 seconds)
        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self._update_statistics)
        self.stats_timer.start(10000)  # 10 second refresh

        # Timer for network info update (every 30 seconds)
        self.net_timer = QTimer(self)
        self.net_timer.timeout.connect(self.update_network_info)
        self.net_timer.start(30000)  # 30 seconds
        
        # Remove the log refresh timer - the log viewer now handles this internally
        # The LogUpdater thread in LogViewerWidget will handle real-time updates

    def _update_statistics(self):
        """Update various statistics displays"""
        if not self.firewall_controller or not self.logger:
            return
            
        # Get active connections count
        connections = self.networks_utils.get_active_connections()
        active_conn_count = len(connections)
        
        # Get processed and blocked packet counts (you would implement these in logger)
        if hasattr(self.logger, 'get_counts'):
            counts = self.logger.get_counts()
            processed = counts.get('processed', 0)
            blocked = counts.get('blocked', 0)
        else:
            processed = 0
            blocked = 0
            
        # Update the status widget
        self.status_widget.update_stats(
            active_connections=active_conn_count,
            packets_processed=processed,
            packets_blocked=blocked
        )
        
    def update_network_info(self):
        """Update the network information in status bar"""
        try:
            ip_addresses = self.networks_utils.get_ip_addresses()
            main_ip = ip_addresses.get('eth0', list(ip_addresses.values())[0] if ip_addresses else 'Unknown')
            self.net_info_label.setText(f"IP: {main_ip}")
        except Exception as e:
            self.net_info_label.setText("IP: Unknown")
    
    def show_alert(self, message, details=None):
        """Show an alert popup"""
        if not self.alert_popup:
            self.alert_popup = AlertPopup()
        
        self.alert_popup.show_alert(message, details)
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self.firewall_controller and self.firewall_controller.is_running:
            reply = QMessageBox.question(self, 'Confirm Exit',
                'The firewall is still running. Do you want to stop it before exiting?',
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
                
            if reply == QMessageBox.Cancel:
                event.ignore()
                return
            elif reply == QMessageBox.Yes:
                self.firewall_controller.stop()
                
        event.accept()