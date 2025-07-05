import sys
import os
from PyQt5.QtWidgets import (QMainWindow, QApplication, QTabWidget, QPushButton, 
                            QLabel, QVBoxLayout, QHBoxLayout, QWidget, QFrame,
                            QSplitter, QMessageBox, QStatusBar, QAction, QMenu, QDialog)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QSize
from PyQt5.QtGui import QIcon, QPixmap, QFont

from gui.rules_editor import RulesEditorWidget
from gui.log_viewer import LogViewerWidget
from gui.alerts_popup import AlertPopup
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
        self.alert_popup = None
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
        header_layout.addWidget(main_title)
        
        main_subtitle = QLabel("Configure rules and monitor network activity")
        main_subtitle.setObjectName("info")
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
    
    # ...existing code...

    def _setup_menu(self):
        """Set up the application menu bar with unified styling"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('&File')
        
        # Import rules action
        import_action = QAction('&Import Rules...', self)
        import_action.setShortcut('Ctrl+I')
        import_action.setStatusTip('Import firewall rules from file')
        import_action.triggered.connect(self._import_rules)
        file_menu.addAction(import_action)
        
        # Export rules action
        export_action = QAction('&Export Rules...', self)
        export_action.setShortcut('Ctrl+E')
        export_action.setStatusTip('Export firewall rules to file')
        export_action.triggered.connect(self._export_rules)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = QAction('E&xit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.setStatusTip('Exit application')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Firewall menu
        firewall_menu = menubar.addMenu('&Firewall')
        
        # Start firewall action
        self.start_action = QAction('&Start Firewall', self)
        self.start_action.setShortcut('Ctrl+S')
        self.start_action.setStatusTip('Start the firewall protection')
        self.start_action.triggered.connect(self._start_firewall)
        firewall_menu.addAction(self.start_action)
        
        # Stop firewall action
        self.stop_action = QAction('St&op Firewall', self)
        self.stop_action.setShortcut('Ctrl+O')
        self.stop_action.setStatusTip('Stop the firewall protection')
        self.stop_action.triggered.connect(self._stop_firewall)
        self.stop_action.setEnabled(False)
        firewall_menu.addAction(self.stop_action)
        
        firewall_menu.addSeparator()
        
        # Reset rules action
        reset_action = QAction('&Reset Rules', self)
        reset_action.setStatusTip('Reset firewall rules to default')
        reset_action.triggered.connect(self._reset_rules)
        firewall_menu.addAction(reset_action)
        
        # View menu
        view_menu = menubar.addMenu('&View')
        
        # Refresh logs action
        refresh_action = QAction('&Refresh Logs', self)
        refresh_action.setShortcut('F5')
        refresh_action.setStatusTip('Refresh activity logs')
        refresh_action.triggered.connect(self._refresh_logs)
        view_menu.addAction(refresh_action)
        
        # Clear logs action
        clear_logs_action = QAction('&Clear Logs', self)
        clear_logs_action.setStatusTip('Clear all activity logs')
        clear_logs_action.triggered.connect(self._clear_logs)
        view_menu.addAction(clear_logs_action)
        
        # Help menu
        help_menu = menubar.addMenu('&Help')
        
        # About action
        about_action = QAction('&About', self)
        about_action.setStatusTip('Show information about SecureShield Firewall')
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        
        # Help action
        help_action = QAction('&Help', self)
        help_action.setShortcut('F1')
        help_action.setStatusTip('Show help documentation')
        help_action.triggered.connect(self._show_help)
        help_menu.addAction(help_action)

    def _setup_timers(self):
        """Set up timers for periodic updates"""
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_status)
        self.status_timer.start(5000)  # Update every 5 seconds
        
        # Network info update timer
        self.network_timer = QTimer()
        self.network_timer.timeout.connect(self.update_network_info)
        self.network_timer.start(10000)  # Update every 10 seconds

    def _check_permissions(self):
        """Check and display permission warnings"""
        if not PermissionChecker.is_admin():
            self.statusBar().showMessage(
                "Warning: Administrator privileges required for full functionality", 
                10000
            )

    def update_network_info(self):
        """Update network information in the status bar"""
        try:
            info = self.networks_utils.get_network_interfaces()
            active_interfaces = [iface for iface in info if iface.get('is_up', False)]
            self.net_info_label.setText(f"Active Interfaces: {len(active_interfaces)}")
        except Exception as e:
            self.net_info_label.setText("Network Info: Unavailable")

    def _toggle_firewall_controller(self, enabled):
        """Handle firewall toggle from status widget"""
        if enabled:
            self._start_firewall()
        else:
            self._stop_firewall()

    def _start_firewall(self):
        """Start the firewall"""
        if not self.firewall_controller:
            QMessageBox.warning(self, "Error", "Firewall controller not initialized")
            return
            
        try:
            success = self.firewall_controller.start()
            if success:
                self.status_widget.update_status(True)
                self.start_action.setEnabled(False)
                self.stop_action.setEnabled(True)
                self.statusBar().showMessage("Firewall started successfully", 3000)
                
                # Initialize alert_popup if not already done
                if not self.alert_popup:
                    self.alert_popup = AlertPopup(self)
                
                # Show system notification if available
                if hasattr(self.alert_popup, 'show_system_event'):
                    self.alert_popup.show_system_event(
                        "Firewall Started", 
                        "SecureShield Firewall protection is now active"
                    )
            else:
                QMessageBox.warning(self, "Error", "Failed to start firewall")
                self.status_widget.update_status(False)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start firewall: {str(e)}")
            self.status_widget.update_status(False)

    def _stop_firewall(self):
        """Stop the firewall"""
        if not self.firewall_controller:
            QMessageBox.warning(self, "Error", "Firewall controller not initialized")
            return
            
        try:
            success = self.firewall_controller.stop()
            if success:
                self.status_widget.update_status(False)
                self.start_action.setEnabled(True)
                self.stop_action.setEnabled(False)
                self.statusBar().showMessage("Firewall stopped", 3000)
                
                # Initialize alert_popup if not already done
                if not self.alert_popup:
                    self.alert_popup = AlertPopup(self)
                
                # Show system notification if available
                if hasattr(self.alert_popup, 'show_system_event'):
                    self.alert_popup.show_system_event(
                        "Firewall Stopped", 
                        "SecureShield Firewall protection has been disabled"
                    )
            else:
                QMessageBox.warning(self, "Error", "Failed to stop firewall")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop firewall: {str(e)}")


    def _update_status(self):
        """Update the firewall status and statistics"""
        if not self.firewall_controller:
            return
            
        try:
            status = self.firewall_controller.status()
            
            # Update status widget
            is_running = status.get('running', False)
            self.status_widget.update_status(is_running)
            
            # Update statistics
            stats = status.get('statistics', {})
            self.status_widget.update_stats(
                active_connections=stats.get('active_connections', 0),
                packets_processed=stats.get('packets_processed', 0),
                packets_blocked=stats.get('packets_blocked', 0)
            )
            
            # Update menu actions
            self.start_action.setEnabled(not is_running)
            self.stop_action.setEnabled(is_running)
            
        except Exception as e:
            print(f"Error updating status: {e}")

    def _show_blocked_alert(self, packet_info):
        """Show an alert for blocked connections"""
        if not self.alert_popup:
            self.alert_popup = AlertPopup(self)
        
        src_ip = packet_info.get('src_ip', 'unknown')
        dst_ip = packet_info.get('dst_ip', 'unknown') 
        dst_port = packet_info.get('dst_port', 'unknown')
        protocol = packet_info.get('protocol_name', 'unknown')
        
        self.alert_popup.show_blocked_connection(src_ip, dst_ip, dst_port, protocol)

    def _import_rules(self):
        """Import firewall rules from a file"""
        try:
            from PyQt5.QtWidgets import QFileDialog
            filename, _ = QFileDialog.getOpenFileName(
                self, 
                "Import Rules", 
                "", 
                "JSON Files (*.json);;All Files (*)"
            )
            
            if filename and self.rule_manager:
                # Import rules logic would go here
                success = self.rule_manager.import_rules(filename)
                if success:
                    self.rules_editor.load_rules()
                    QMessageBox.information(self, "Success", "Rules imported successfully")
                    self.statusBar().showMessage("Rules imported", 3000)
                else:
                    QMessageBox.warning(self, "Error", "Failed to import rules")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Import failed: {str(e)}")

    def _export_rules(self):
        """Export firewall rules to a file"""
        try:
            from PyQt5.QtWidgets import QFileDialog
            filename, _ = QFileDialog.getSaveFileName(
                self, 
                "Export Rules", 
                "firewall_rules.json", 
                "JSON Files (*.json);;All Files (*)"
            )
            
            if filename and self.rule_manager:
                # Export rules logic would go here
                success = self.rule_manager.export_rules(filename)
                if success:
                    QMessageBox.information(self, "Success", f"Rules exported to {filename}")
                    self.statusBar().showMessage("Rules exported", 3000)
                else:
                    QMessageBox.warning(self, "Error", "Failed to export rules")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")

    def _reset_rules(self):
        """Reset firewall rules to default"""
        reply = QMessageBox.question(
            self, 
            "Confirm Reset", 
            "Are you sure you want to reset all rules to default?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes and self.rule_manager:
            try:
                self.rule_manager.reset_to_default()
                self.rules_editor.load_rules()
                QMessageBox.information(self, "Success", "Rules reset to default")
                self.statusBar().showMessage("Rules reset", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Reset failed: {str(e)}")

    def _refresh_logs(self):
        """Refresh the activity logs"""
        try:
            if hasattr(self.log_viewer, '_apply_filters'):
                self.log_viewer._apply_filters()
                self.statusBar().showMessage("Logs refreshed", 2000)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to refresh logs: {str(e)}")

    def _clear_logs(self):
        """Clear all activity logs"""
        reply = QMessageBox.question(
            self, 
            "Confirm Clear", 
            "Are you sure you want to clear all activity logs?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                if hasattr(self.log_viewer, '_clear_display'):
                    self.log_viewer._clear_display()
                if self.logger:
                    # Clear logs in logger if method exists
                    if hasattr(self.logger, 'clear_logs'):
                        self.logger.clear_logs()
                
                QMessageBox.information(self, "Success", "Logs cleared successfully")
                self.statusBar().showMessage("Logs cleared", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to clear logs: {str(e)}")

    def _show_about(self):
        """Show about dialog with unified styling"""
        about_dialog = QDialog(self)
        about_dialog.setWindowTitle("About SecureShield Firewall")
        about_dialog.setFixedSize(450, 350)
        about_dialog.setStyleSheet("""
            QDialog {
                background-color: #1E1E1E;
                color: #D4D4D4;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Logo/Title
        title_label = QLabel("SecureShield Firewall")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #007ACC;
                background-color: transparent;
            }
        """)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Version
        version_label = QLabel("Version 1.0.0")
        version_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #D4D4D4;
                background-color: transparent;
            }
        """)
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)
        
        # Description
        desc_label = QLabel(
            "A comprehensive network security solution providing "
            "advanced firewall protection with real-time monitoring "
            "and intelligent threat detection."
        )
        desc_label.setStyleSheet("""
            QLabel {
                font-size: 11px;
                color: #A0A0A0;
                background-color: transparent;
                padding: 15px;
            }
        """)
        desc_label.setWordWrap(True)
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        # Copyright
        copyright_label = QLabel("© 2024 SecureShield. All rights reserved.")
        copyright_label.setStyleSheet("""
            QLabel {
                font-size: 10px;
                color: #A0A0A0;
                background-color: transparent;
            }
        """)
        copyright_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(copyright_label)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 30px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #1F8AD2;
            }
        """)
        close_btn.clicked.connect(about_dialog.accept)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        about_dialog.setLayout(layout)
        about_dialog.exec_()

    def _show_help(self):
        """Show help dialog with unified styling"""
        help_dialog = QDialog(self)
        help_dialog.setWindowTitle("SecureShield Firewall Help")
        help_dialog.setFixedSize(600, 500)
        help_dialog.setStyleSheet("""
            QDialog {
                background-color: #1E1E1E;
                color: #D4D4D4;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Title
        title_label = QLabel("Help & Documentation")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #007ACC;
                background-color: transparent;
                margin-bottom: 15px;
            }
        """)
        layout.addWidget(title_label)
        
        # Help content
        help_text = """
<div style="color: #D4D4D4; font-size: 11px; line-height: 1.4;">
<h3 style="color: #007ACC;">Getting Started</h3>
<p>1. <strong>Enable Firewall:</strong> Click the "Enable Firewall" button in the status panel</p>
<p>2. <strong>Configure Rules:</strong> Use the Firewall Rules tab to add custom rules</p>
<p>3. <strong>Monitor Activity:</strong> Check the Activity Logs tab for real-time monitoring</p>

<h3 style="color: #007ACC;">Firewall Rules</h3>
<p>• <strong>Add Rule:</strong> Click "Add Rule" to create new filtering rules</p>
<p>• <strong>Edit Rule:</strong> Select a rule and click "Edit Rule" to modify</p>
<p>• <strong>Delete Rule:</strong> Select a rule and click "Delete Rule" to remove</p>

<h3 style="color: #007ACC;">Activity Monitoring</h3>
<p>• <strong>Connection Logs:</strong> View all network connections and their status</p>
<p>• <strong>System Events:</strong> Monitor firewall system events and alerts</p>
<p>• <strong>Filters:</strong> Use filters to find specific activities or time periods</p>

<h3 style="color: #007ACC;">Keyboard Shortcuts</h3>
<p>• <strong>Ctrl+S:</strong> Start Firewall</p>
<p>• <strong>Ctrl+O:</strong> Stop Firewall</p>
<p>• <strong>F5:</strong> Refresh Logs</p>
<p>• <strong>F1:</strong> Show Help</p>
<p>• <strong>Ctrl+Q:</strong> Exit Application</p>
</div>
        """
        
        help_content = QLabel(help_text)
        help_content.setStyleSheet("""
            QLabel {
                background-color: #252526;
                border: 1px solid #454545;
                border-radius: 8px;
                padding: 20px;
            }
        """)
        help_content.setWordWrap(True)
        help_content.setTextFormat(Qt.RichText)
        layout.addWidget(help_content)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 30px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #1F8AD2;
            }
        """)
        close_btn.clicked.connect(help_dialog.accept)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)
        
        help_dialog.setLayout(layout)
        help_dialog.exec_()

    def closeEvent(self, event):
        """Handle application close event"""
        # Stop firewall if running
        if self.firewall_controller and hasattr(self.firewall_controller, 'is_running'):
            if self.firewall_controller.is_running():
                reply = QMessageBox.question(
                    self, 
                    "Firewall Running", 
                    "The firewall is currently running. Do you want to stop it before exiting?",
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
                )
                
                if reply == QMessageBox.Cancel:
                    event.ignore()
                    return
                elif reply == QMessageBox.Yes:
                    try:
                        self.firewall_controller.stop()
                    except Exception as e:
                        print(f"Error stopping firewall: {e}")
        
        # Clean up resources
        if hasattr(self, 'status_timer'):
            self.status_timer.stop()
        if hasattr(self, 'network_timer'):
            self.network_timer.stop()
        
        # Clean up log viewer
        if hasattr(self.log_viewer, 'closeEvent'):
            self.log_viewer.closeEvent(event)
        
        event.accept()

    def sizeHint(self):
        """Return preferred size for the main window"""
        return QSize(1200, 800)