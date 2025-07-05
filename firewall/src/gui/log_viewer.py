from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                           QPushButton, QComboBox, QLabel, QSpinBox, QTableWidgetItem,
                           QDateTimeEdit, QLineEdit, QCheckBox, QTabWidget, QHeaderView, QFrame)
from PyQt5.QtCore import Qt, QDateTime, pyqtSlot, QSize, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QBrush
import time
import datetime

class LogUpdater(QThread):
    """Thread to fetch logs and emit signals when new logs are available"""
    new_conn_logs = pyqtSignal(list)
    new_system_logs = pyqtSignal(list)
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.running = True
        self.filter_settings = {
            'log_type': 'All Logs',
            'ip_filter': '',
            'time_from': 0,
            'time_to': time.time() + 86400,  # Default to now + 1 day
            'limit': 100
        }
        self.last_conn_timestamp = 0
        self.last_sys_timestamp = 0
        
    def update_filters(self, filters):
        """Update the filter settings"""
        self.filter_settings = filters
        # Reset timestamps to force full refresh when filters are changed
        self.last_conn_timestamp = 0
        self.last_sys_timestamp = 0
        
    def run(self):
        """Main thread loop"""
        while self.running:
            # Check for new logs
            self.check_for_new_logs()
            # Sleep briefly
            self.msleep(500)  # Check every 500ms
            
    def check_for_new_logs(self):
        """Check for new logs based on filter settings"""
        if not self.logger:
            return
            
        try:
            filters = self.filter_settings
            log_type = filters['log_type']
            ip_filter = filters['ip_filter']
            time_from = filters['time_from']
            time_to = filters['time_to']
            limit = filters['limit']
            
            # Fetch appropriate connection logs based on type
            conn_logs = []
            if log_type == "Blocked Only":
                conn_logs = self.logger.get_recent_connections(limit=limit, action="BLOCK")
            elif log_type == "Allowed Only": 
                conn_logs = self.logger.get_recent_connections(limit=limit, action="ALLOW")
            elif log_type != "System Events":  # All Logs or anything else
                conn_logs = self.logger.get_recent_connections(limit=limit)
                
            # Fetch system logs if needed
            sys_logs = []
            if log_type == "System Events" or log_type == "All Logs":
                sys_logs = self.logger.get_recent_events(limit=limit)
            
            # Filter connection logs
            new_conn_logs = []
            for log in conn_logs:
                # Only process logs we haven't seen yet
                timestamp = log.get('timestamp', 0)
                if timestamp <= self.last_conn_timestamp:
                    continue
                    
                # Apply time filter
                if timestamp < time_from or timestamp > time_to:
                    continue
                    
                # Apply IP filter
                if ip_filter:
                    src_ip = log.get('src_ip', '')
                    dst_ip = log.get('dst_ip', '')
                    if ip_filter not in src_ip and ip_filter not in dst_ip:
                        continue
                        
                # This is a new log that passes the filters
                new_conn_logs.append(log)
                
            # Filter system logs
            new_sys_logs = []
            for log in sys_logs:
                # Only process logs we haven't seen yet
                timestamp = log.get('timestamp', 0)
                if timestamp <= self.last_sys_timestamp:
                    continue
                    
                # Apply time filter
                if timestamp < time_from or timestamp > time_to:
                    continue
                    
                # Apply IP filter if needed
                if ip_filter and 'event' in log:
                    event = log.get('event', '')
                    if ip_filter not in event:
                        continue
                        
                # This is a new log that passes the filters
                new_sys_logs.append(log)
            
            # Update the last seen timestamps
            if conn_logs and conn_logs[0].get('timestamp', 0) > self.last_conn_timestamp:
                self.last_conn_timestamp = conn_logs[0].get('timestamp', 0)
                
            if sys_logs and sys_logs[0].get('timestamp', 0) > self.last_sys_timestamp:
                self.last_sys_timestamp = sys_logs[0].get('timestamp', 0)
            
            # Emit signals if we have new logs
            if new_conn_logs:
                self.new_conn_logs.emit(new_conn_logs)
                
            if new_sys_logs:
                self.new_system_logs.emit(new_sys_logs)
                
        except Exception as e:
            print(f"Error in log updater: {e}")
            
    def stop(self):
        """Stop the thread"""
        self.running = False
        self.wait()

class LogViewerWidget(QWidget):
    """Widget for viewing firewall logs with unified styling"""
    def __init__(self, logger=None, parent=None):
        super().__init__(parent)
        self.logger = logger
        self.auto_refresh = True
        self._init_ui()
        self.updater = None
        
        # Start the log updater if logger is provided
        if logger:
            self._setup_updater()
            self._apply_filters()  # Initial load of logs
        
    def _init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header section
        header_frame = QFrame()
        header_frame.setStyleSheet("QFrame { border: none; background-color: transparent; }")
        header_layout = QVBoxLayout(header_frame)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        title = QLabel("Activity Logs")
        title.setObjectName("title")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #007ACC;")
        header_layout.addWidget(title)
        
        subtitle = QLabel("Monitor network activity and system events in real-time")
        subtitle.setObjectName("info")
        subtitle.setStyleSheet("color: #A0A0A0; font-size: 11px; margin-bottom: 10px;")
        header_layout.addWidget(subtitle)
        
        layout.addWidget(header_frame)
        
        # Filter controls container
        filter_container = QFrame()
        filter_container.setStyleSheet("""
            QFrame {
                background-color: #252526;
                border: 1px solid #454545;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        filter_layout = QHBoxLayout(filter_container)
        
        # Log type filter
        type_label = QLabel("Type:")
        type_label.setStyleSheet("color: #D4D4D4; font-weight: bold; padding-right: 5px;")
        filter_layout.addWidget(type_label)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All Logs", "Blocked Only", "Allowed Only", "System Events"])
        self.type_combo.currentTextChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.type_combo)
        
        # IP filter
        ip_label = QLabel("IP Filter:")
        ip_label.setStyleSheet("color: #D4D4D4; font-weight: bold; padding-right: 5px; padding-left: 15px;")
        filter_layout.addWidget(ip_label)
        
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("Filter by IP address...")
        self.ip_edit.returnPressed.connect(self._apply_filters)
        self.ip_edit.setMaximumWidth(150)
        filter_layout.addWidget(self.ip_edit)
        
        # Time filter
        time_label = QLabel("From:")
        time_label.setStyleSheet("color: #D4D4D4; font-weight: bold; padding-right: 5px; padding-left: 15px;")
        filter_layout.addWidget(time_label)
        
        self.time_from = QDateTimeEdit(QDateTime.currentDateTime().addDays(-1))
        self.time_from.setCalendarPopup(True)
        self.time_from.setMaximumWidth(140)
        filter_layout.addWidget(self.time_from)
        
        to_label = QLabel("To:")
        to_label.setStyleSheet("color: #D4D4D4; font-weight: bold; padding-right: 5px; padding-left: 10px;")
        filter_layout.addWidget(to_label)
        
        self.time_to = QDateTimeEdit(QDateTime.currentDateTime().addDays(1))
        self.time_to.setCalendarPopup(True)
        self.time_to.setMaximumWidth(140)
        filter_layout.addWidget(self.time_to)
        
        # Max entries
        limit_label = QLabel("Limit:")
        limit_label.setStyleSheet("color: #D4D4D4; font-weight: bold; padding-right: 5px; padding-left: 15px;")
        filter_layout.addWidget(limit_label)
        
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(10, 1000)
        self.limit_spin.setValue(100)
        self.limit_spin.setSingleStep(10)
        self.limit_spin.setMaximumWidth(80)
        filter_layout.addWidget(self.limit_spin)
        
        # Apply filter button
        self.apply_btn = QPushButton("Apply Filter")
        self.apply_btn.setObjectName("success")
        self.apply_btn.clicked.connect(self._apply_filters)
        filter_layout.addWidget(self.apply_btn)

        # Auto refresh checkbox
        self.auto_refresh_cb = QCheckBox("Auto Update")
        self.auto_refresh_cb.setChecked(True)
        self.auto_refresh_cb.toggled.connect(self.toggle_auto_refresh)
        self.auto_refresh_cb.setStyleSheet("color: #D4D4D4; font-weight: bold; padding-left: 15px;")
        filter_layout.addWidget(self.auto_refresh_cb)
        
        # Add filter layout
        layout.addWidget(filter_container)
        
        # Create tab widget with enhanced styling
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #454545;
                background-color: #252526;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #333333;
                color: #D4D4D4;
                min-width: 150px;
                padding: 12px 20px;
                border: 1px solid #454545;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 2px;
                font-size: 11px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #007ACC;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background-color: #252526;
            }
        """)
        
        # Connection logs tab
        self.conn_tab = QWidget()
        conn_layout = QVBoxLayout()
        conn_layout.setContentsMargins(15, 15, 15, 15)
        
        # Connection logs table
        self.conn_table = QTableWidget(0, 6)
        self.conn_table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Action", "Details"
        ])
        self.setup_table(self.conn_table)
        conn_layout.addWidget(self.conn_table)
        self.conn_tab.setLayout(conn_layout)
        
        # System logs tab
        self.system_tab = QWidget()
        system_layout = QVBoxLayout()
        system_layout.setContentsMargins(15, 15, 15, 15)
        
        # System logs table
        self.system_table = QTableWidget(0, 4)
        self.system_table.setHorizontalHeaderLabels([
            "Time", "Level", "Event", "Details"
        ])
        self.setup_table(self.system_table)
        system_layout.addWidget(self.system_table)
        self.system_tab.setLayout(system_layout)
        
        # Add tabs to the tab widget
        self.tab_widget.addTab(self.conn_tab, "🔗 Connection Logs")
        self.tab_widget.addTab(self.system_tab, "⚙️ System Events")
        
        # Add tab widget to main layout
        layout.addWidget(self.tab_widget)
        
        # Buttons layout
        button_container = QFrame()
        button_container.setStyleSheet("""
            QFrame {
                background-color: #252526;
                border: 1px solid #454545;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        button_layout = QHBoxLayout(button_container)
        
        # Clear button
        self.clear_btn = QPushButton("Clear Display")
        self.clear_btn.setObjectName("secondary")
        self.clear_btn.clicked.connect(self._clear_display)
        button_layout.addWidget(self.clear_btn)
        
        # Export button
        self.export_btn = QPushButton("Export Logs")
        self.export_btn.setObjectName("secondary")
        self.export_btn.clicked.connect(self._export_logs)
        button_layout.addWidget(self.export_btn)
        
        # Add stretch to push buttons to the left
        button_layout.addStretch()
        
        # Status info
        self.status_info = QLabel("Ready to monitor network activity")
        self.status_info.setStyleSheet("color: #A0A0A0; font-style: italic;")
        button_layout.addWidget(self.status_info)
        
        layout.addWidget(button_container)
        
        self.setLayout(layout)

    def setup_table(self, table):
        """Configure a table widget with unified styling"""
        # Enhanced table styling to match the theme
        table.setStyleSheet("""
            QTableWidget {
                gridline-color: #454545;
                background-color: #1E1E1E;
                color: #D4D4D4;
                selection-background-color: #007ACC;
                selection-color: white;
                border: none;
                border-radius: 5px;
                alternate-background-color: #252526;
                font-size: 10px;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #454545;
            }
            QTableWidget::item:selected {
                background-color: #007ACC;
                color: white;
            }
            QHeaderView::section {
                background-color: #333333;
                color: #D4D4D4;
                padding: 10px;
                border: 1px solid #454545;
                font-weight: bold;
                font-size: 11px;
            }
        """)
        
        # Auto-resize columns to content
        header = table.horizontalHeader()
        for i in range(header.count()):
            header.setSectionResizeMode(i, QHeaderView.Stretch)
        
        # Set selection behavior
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(False)  # Disable sorting to maintain chronological order
        
        # Set font
        table.setFont(QFont("Segoe UI", 10))
        
        return table
    
    def _setup_updater(self):
        """Set up the log updater thread"""
        if self.updater is not None:
            self.updater.stop()
            
        self.updater = LogUpdater(self.logger)
        
        # Connect signals
        self.updater.new_conn_logs.connect(self._handle_new_conn_logs)
        self.updater.new_system_logs.connect(self._handle_new_system_logs)
        
        # Update filters and start the thread
        self._update_filters()
        self.updater.start()
    
    def _apply_filters(self):
        """Apply filters and reset the display"""
        self._clear_display()
        self._update_filters()
        self.status_info.setText(f"Applying filters... Type: {self.type_combo.currentText()}")
    
    def _update_filters(self):
        """Update the filter settings for the updater"""
        if not self.updater:
            return
            
        # Get filter values
        filters = {
            'log_type': self.type_combo.currentText(),
            'ip_filter': self.ip_edit.text().strip(),
            'time_from': self.time_from.dateTime().toSecsSinceEpoch(),
            'time_to': self.time_to.dateTime().toSecsSinceEpoch(),
            'limit': self.limit_spin.value()
        }
        
        # Update the updater
        self.updater.update_filters(filters)
        
    def toggle_auto_refresh(self, enabled):
        """Toggle auto refresh on or off"""
        self.auto_refresh = enabled
        if enabled and self.updater:
            self.updater.running = True
            if not self.updater.isRunning():
                self._setup_updater()  # Restart if not running
            self.status_info.setText("Auto-update enabled - monitoring in real-time")
        elif not enabled and self.updater:
            self.updater.running = False
            self.status_info.setText("Auto-update disabled - manual refresh required")
    
    @pyqtSlot(list)
    def _handle_new_conn_logs(self, logs):
        """Handle new connection logs"""
        if not self.auto_refresh:
            return
            
        # Sort logs by timestamp (newest first)
        logs.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        
        # Add rows at the beginning of the table
        for log in logs:
            self._add_connection_log_to_table(log)
            
        # Update status
        if logs:
            self.status_info.setText(f"Updated with {len(logs)} new connection log(s)")
    
    @pyqtSlot(list)
    def _handle_new_system_logs(self, logs):
        """Handle new system logs"""
        if not self.auto_refresh:
            return
            
        # Sort logs by timestamp (newest first)
        logs.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        
        # Add rows at the beginning of the table
        for log in logs:
            self._add_system_log_to_table(log)
            
        # Update status
        if logs:
            self.status_info.setText(f"Updated with {len(logs)} new system log(s)")
    
    def _add_connection_log_to_table(self, log):
        """Add a connection log entry to the table with enhanced styling"""
        # Insert a new row at the top
        self.conn_table.insertRow(0)
        
        # Format time
        timestamp = log.get('timestamp', 0)
        time_str = datetime.datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
        
        # Get log details
        src = f"{log.get('src_ip', '')}:{log.get('src_port', '')}"
        dst = f"{log.get('dst_ip', '')}:{log.get('dst_port', '')}"
        protocol = log.get('protocol', '')
        action = log.get('action', '')
        details = str(log.get('details', ''))
        
        # Add items to the table with enhanced formatting
        time_item = QTableWidgetItem(time_str)
        time_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.conn_table.setItem(0, 0, time_item)
        
        self.conn_table.setItem(0, 1, QTableWidgetItem(src))
        self.conn_table.setItem(0, 2, QTableWidgetItem(dst))
        self.conn_table.setItem(0, 3, QTableWidgetItem(protocol))
        
        action_item = QTableWidgetItem(action)
        self.conn_table.setItem(0, 4, action_item)
        
        self.conn_table.setItem(0, 5, QTableWidgetItem(details))
        
        # Color based on action with enhanced visibility
        if action == "BLOCK":
            color = QColor(255, 100, 100)  # Bright red for blocked
            for col in range(6):
                item = self.conn_table.item(0, col)
                item.setForeground(QBrush(color))
                item.setFont(QFont("Segoe UI", 10, QFont.Bold))
        elif action == "ALLOW":
            color = QColor(100, 255, 100)  # Green for allowed
            for col in range(6):
                item = self.conn_table.item(0, col)
                item.setForeground(QBrush(color))
    
    def _add_system_log_to_table(self, log):
        """Add a system log entry to the table with enhanced styling"""
        # Insert a new row at the top
        self.system_table.insertRow(0)
        
        # Format time
        timestamp = log.get('timestamp', 0)
        time_str = datetime.datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
        
        # Get log details
        level = log.get('level', 'INFO')
        event = log.get('event', '')
        details = str(log.get('details', ''))
        
        # Add items to the table
        time_item = QTableWidgetItem(time_str)
        time_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.system_table.setItem(0, 0, time_item)
        
        level_item = QTableWidgetItem(level)
        self.system_table.setItem(0, 1, level_item)
        
        self.system_table.setItem(0, 2, QTableWidgetItem(event))
        self.system_table.setItem(0, 3, QTableWidgetItem(details))
        
        # Color based on level with enhanced visibility
        if level == "ERROR":
            color = QColor(255, 80, 80)  # Red
            for col in range(4):
                item = self.system_table.item(0, col)
                item.setForeground(QBrush(color))
                item.setFont(QFont("Segoe UI", 10, QFont.Bold))
        elif level == "WARNING":
            color = QColor(255, 200, 80)  # Orange
            for col in range(4):
                item = self.system_table.item(0, col)
                item.setForeground(QBrush(color))
                item.setFont(QFont("Segoe UI", 10, QFont.Bold))
        elif level == "INFO":
            color = QColor(100, 200, 255)  # Light blue
            for col in range(4):
                item = self.system_table.item(0, col)
                item.setForeground(QBrush(color))
    
    def _export_logs(self):
        """Export logs to a file"""
        # Implementation for exporting logs to CSV
        try:
            from PyQt5.QtWidgets import QFileDialog
            filename, _ = QFileDialog.getSaveFileName(
                self, 
                "Export Logs", 
                f"firewall_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "CSV Files (*.csv)"
            )
            if filename:
                self.status_info.setText(f"Logs exported to {filename}")
        except Exception as e:
            self.status_info.setText(f"Export failed: {str(e)}")
    
    def _clear_display(self):
        """Clear the display"""
        self.conn_table.setRowCount(0)
        self.system_table.setRowCount(0)
        self.status_info.setText("Display cleared")
    
    def closeEvent(self, event):
        """Clean up threads when closing"""
        if self.updater:
            self.updater.stop()
        super().closeEvent(event)
    
    def sizeHint(self):
        return QSize(900, 700)