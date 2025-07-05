import sys
import os
from PyQt5.QtWidgets import (QMainWindow, QApplication, QTabWidget, QPushButton, 
                            QLabel, QVBoxLayout, QHBoxLayout, QWidget, QFrame,
                            QSplitter, QMessageBox, QStatusBar, QAction, QMenu, QDialog)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QSize
from PyQt5.QtGui import QIcon, QPixmap, QFont

from gui.rules_editor import RulesEditorWidget
from gui.log_viewer import LogViewerWidget
from utils.permissions import PermissionChecker
from utils.network_utils import NetworkUtils

class FirewallStatusWidget(QFrame):
    """Widget displaying firewall status and controls - matching antivirus/password manager style"""
    toggled = pyqtSignal(bool)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self._running = False
        self._initUI()
        
    def _initUI(self):
        # Main layout with padding matching antivirus style
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 30, 20, 30)
        layout.setSpacing(20)
        
        # Logo/Title section
        logo_frame = QFrame()
        logo_frame.setStyleSheet("QFrame { border: none; background-color: transparent; }")
        logo_layout = QVBoxLayout(logo_frame)
        logo_layout.setContentsMargins(0, 0, 0, 0)
        
        title = QLabel("SecureShield")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(title)
        
        subtitle = QLabel("Firewall Protection")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(subtitle)
        
        layout.addWidget(logo_frame)
        
        # Status section
        status_frame = QFrame()
        status_frame.setStyleSheet("QFrame { border: none; background-color: transparent; }")
        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(0, 0, 0, 0)
        
        status_title = QLabel("Protection Status")
        status_title.setObjectName("subtitle")
        status_title.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(status_title)
        
        # Status indicator
        self.status_label = QLabel("INACTIVE")
        self.status_label.setObjectName("status_inactive")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("""
            QLabel {
                color: #F14C4C;
                font-weight: bold;
                font-size: 18px;
                padding: 10px;
                border: 2px solid #F14C4C;
                border-radius: 8px;
                background-color: #252526;
            }
        """)
        status_layout.addWidget(self.status_label)
        
        layout.addWidget(status_frame)
        
        # Toggle button with antivirus styling
        self.toggle_btn = QPushButton("Enable Firewall")
        self.toggle_btn.setFixedHeight(45)
        self.toggle_btn.setObjectName("success")
        self.toggle_btn.clicked.connect(self._toggle_firewall)
        layout.addWidget(self.toggle_btn)
        
        # Statistics section
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background-color: #252526;
                border: 1px solid #454545;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        stats_layout = QVBoxLayout(stats_frame)
        
        stats_title = QLabel("Network Statistics")
        stats_title.setObjectName("subtitle")
        stats_title.setAlignment(Qt.AlignCenter)
        stats_layout.addWidget(stats_title)
        
        # Individual stats with antivirus styling
        self.conn_label = QLabel("Active Connections: 0")
        self.conn_label.setObjectName("info")
        self.conn_label.setStyleSheet("color: #D4D4D4; padding: 5px;")
        stats_layout.addWidget(self.conn_label)
        
        self.packets_label = QLabel("Packets Processed: 0")
        self.packets_label.setObjectName("info")
        self.packets_label.setStyleSheet("color: #D4D4D4; padding: 5px;")
        stats_layout.addWidget(self.packets_label)
        
        self.blocked_label = QLabel("Packets Blocked: 0")
        self.blocked_label.setObjectName("info")
        self.blocked_label.setStyleSheet("color: #F14C4C; padding: 5px; font-weight: bold;")
        stats_layout.addWidget(self.blocked_label)
        
        layout.addWidget(stats_frame)
        
        # Add stretch to push everything up
        layout.addStretch()
        
        # Version info at bottom
        version_frame = QFrame()
        version_frame.setStyleSheet("QFrame { border: none; background-color: transparent; }")
        version_layout = QVBoxLayout(version_frame)
        version_layout.setContentsMargins(0, 0, 0, 0)
        
        version_label = QLabel("Firewall v1.0")
        version_label.setObjectName("info")
        version_label.setAlignment(Qt.AlignCenter)
        version_layout.addWidget(version_label)
        
        layout.addWidget(version_frame)
        
        self.setLayout(layout)
        
        # Apply overall frame styling
        self.setStyleSheet("""
            FirewallStatusWidget {
                background-color: #1E1E1E;
                border-right: 1px solid #454545;
            }
        """)
        
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
            self.status_label.setObjectName("status_active")
            self.status_label.setStyleSheet("""
                QLabel {
                    color: #6A9955;
                    font-weight: bold;
                    font-size: 18px;
                    padding: 10px;
                    border: 2px solid #6A9955;
                    border-radius: 8px;
                    background-color: #252526;
                }
            """)
            self.toggle_btn.setText("Disable Firewall")
            self.toggle_btn.setObjectName("danger")
            self.toggle_btn.setStyleSheet("""
                QPushButton {
                    background-color: #F14C4C;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    padding: 8px 16px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #E53E3E;
                }
            """)
        else:
            self.status_label.setText("INACTIVE")
            self.status_label.setObjectName("status_inactive")
            self.status_label.setStyleSheet("""
                QLabel {
                    color: #F14C4C;
                    font-weight: bold;
                    font-size: 18px;
                    padding: 10px;
                    border: 2px solid #F14C4C;
                    border-radius: 8px;
                    background-color: #252526;
                }
            """)
            self.toggle_btn.setText("Enable Firewall")
            self.toggle_btn.setObjectName("success")
            self.toggle_btn.setStyleSheet("""
                QPushButton {
                    background-color: #6A9955;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    padding: 8px 16px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #5A8A4A;
                }
            """)
            
    def update_stats(self, active_connections=0, packets_processed=0, packets_blocked=0):
        """Update the network statistics display"""
        self.conn_label.setText(f"Active Connections: {active_connections}")
        self.packets_label.setText(f"Packets Processed: {packets_processed}")
        self.blocked_label.setText(f"Packets Blocked: {packets_blocked}")

class MainWindow(QMainWindow):
    """Main application window with unified antivirus styling"""
    blocked_connection_signal = pyqtSignal(dict)

    def __init__(self, firewall_controller=None, rule_manager=None, logger=None):
        super().__init__()
        self.firewall_controller = firewall_controller
        self.rule_manager = rule_manager
        self.logger = logger
        self.networks_utils = NetworkUtils()
        self.blocked_connection_signal.connect(self._show_blocked_alert)
        
        self._initUI()
        self._setup_timers()
        self._check_permissions()
        
    def _initUI(self):
        """Initialize the user interface with antivirus styling"""
        self.setWindowTitle("SecureShield Firewall Management")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 600)
        
        # Create central widget and layout
        central_widget = QWidget()
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Left side - Status panel (matching antivirus sidebar)
        self.status_widget = FirewallStatusWidget()
        self.status_widget.setFixedWidth(280)
        self.status_widget.toggled.connect(self._toggle_firewall_controller)
        main_layout.addWidget(self.status_widget)
        
        # Right side - Main content area
        content_widget = QWidget()
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(10, 10, 10, 10)
        
        # Header section for main content
        header_frame = QFrame()
        header_frame.setStyleSheet("QFrame { border: none; background-color: transparent; }")
        header_layout = QVBoxLayout(header_frame)
        header_layout.setContentsMargins(20, 20, 20, 10)
        
        main_title = QLabel("Firewall Management")
        main_title.setObjectName("title")
        main_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #007ACC;")
        header_layout.addWidget(main_title)
        
        main_subtitle = QLabel("Configure rules and monitor network activity")
        main_subtitle.setObjectName("info")
        main_subtitle.setStyleSheet("color: #A0A0A0; font-size: 11px; margin-bottom: 10px;")
        header_layout.addWidget(main_subtitle)
        
        content_layout.addWidget(header_frame)
        
        # Tabbed content area
        self.tab_widget = QTabWidget()
        
        # Rules editor tab
        self.rules_editor = RulesEditorWidget(self.rule_manager)
        self.tab_widget.addTab(self.rules_editor, "🛡️ Firewall Rules")
        
        # Log viewer tab
        self.log_viewer = LogViewerWidget(self.logger)
        self.tab_widget.addTab(self.log_viewer, "📊 Activity Logs")
        
        content_layout.addWidget(self.tab_widget)
        
        content_widget.setLayout(content_layout)
        main_layout.addWidget(content_widget)
        
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
        """Handle blocked connection signal - removed annoying popup"""
        pass

    def _setup_menu(self):
        """Set up the application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('&File')
        
        # Exit action
        exit_action = QAction('E&xit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Firewall menu
        fw_menu = menubar.addMenu('&Firewall')
        
        # Start action
        start_action = QAction('&Start', self)
        start_action.triggered.connect(lambda: self._toggle_firewall_controller(True))
        fw_menu.addAction(start_action)
        
        # Stop action
        stop_action = QAction('St&op', self)
        stop_action.triggered.connect(lambda: self._toggle_firewall_controller(False))
        fw_menu.addAction(stop_action)
        
        fw_menu.addSeparator()
        
        # Reload rules action
        reload_action = QAction('&Reload Rules', self)
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
        self.stats_timer.start(5000)  # 5 second refresh

        # Timer for network info update (every 30 seconds)
        self.net_timer = QTimer(self)
        self.net_timer.timeout.connect(self.update_network_info)
        self.net_timer.start(30000)  # 30 seconds

    def _update_statistics(self):
        """Update various statistics displays"""
        if not self.firewall_controller or not self.logger:
            return
            
        # Get active connections count
        try:
            connections = self.networks_utils.get_active_connections()
            active_conn_count = len(connections)
        except:
            active_conn_count = 0
        
        # Get processed and blocked packet counts
        if hasattr(self.logger, 'get_counts'):
            try:
                counts = self.logger.get_counts()
                processed = counts.get('processed', 0)
                blocked = counts.get('blocked', 0)
            except:
                processed = 0
                blocked = 0
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
            self.net_info_label.setText(f"Network Info: Unavailable")
        except Exception as e:
            self.net_info_label.setText("Network Info: Unavailable")
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self.firewall_controller:
            # Check if firewall is running
            try:
                status = self.firewall_controller.status()
                is_running = status.get('running', False)
                
                if is_running:
                    reply = QMessageBox.question(self, 'Confirm Exit',
                        'The firewall is still running. Do you want to stop it before exiting?',
                        QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
                        
                    if reply == QMessageBox.Cancel:
                        event.ignore()
                        return
                    elif reply == QMessageBox.Yes:
                        self.firewall_controller.stop()
            except:
                pass
                
        event.accept()