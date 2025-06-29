from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                           QPushButton, QComboBox, QLabel, QSpinBox, QTableWidgetItem,
                           QDateTimeEdit, QLineEdit, QCheckBox, QTabWidget, QHeaderView)
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
    """Widget for viewing firewall logs in table format with real-time updates"""
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
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        # Log type filter
        filter_layout.addWidget(QLabel("Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All Logs", "Blocked Only", "Allowed Only", "System Events"])
        self.type_combo.currentTextChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.type_combo)
        
        # IP filter
        filter_layout.addWidget(QLabel("IP:"))
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("Filter by IP...")
        self.ip_edit.returnPressed.connect(self._apply_filters)
        filter_layout.addWidget(self.ip_edit)
        
        # Time filter
        filter_layout.addWidget(QLabel("From:"))
        self.time_from = QDateTimeEdit(QDateTime.currentDateTime().addDays(-1))
        self.time_from.setCalendarPopup(True)
        filter_layout.addWidget(self.time_from)
        
        filter_layout.addWidget(QLabel("To:"))
        self.time_to = QDateTimeEdit(QDateTime.currentDateTime().addDays(1))  # Future time to catch upcoming logs
        self.time_to.setCalendarPopup(True)
        filter_layout.addWidget(self.time_to)
        
        # Max entries
        filter_layout.addWidget(QLabel("Limit:"))
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(10, 1000)
        self.limit_spin.setValue(100)
        self.limit_spin.setSingleStep(10)
        filter_layout.addWidget(self.limit_spin)
        
        # Apply filter button
        self.apply_btn = QPushButton("Apply Filter")
        self.apply_btn.clicked.connect(self._apply_filters)
        filter_layout.addWidget(self.apply_btn)

        # Auto refresh checkbox
        self.auto_refresh_cb = QCheckBox("Auto Update")
        self.auto_refresh_cb.setChecked(True)
        self.auto_refresh_cb.toggled.connect(self.toggle_auto_refresh)
        filter_layout.addWidget(self.auto_refresh_cb)
        
        # Add filter layout
        layout.addLayout(filter_layout)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Connection logs tab
        self.conn_tab = QWidget()
        conn_layout = QVBoxLayout()
        
        # Connection logs table
        self.conn_table = QTableWidget(0, 6)  # Rows will be added dynamically
        self.conn_table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Action", "Details"
        ])
        self.setup_table(self.conn_table)
        conn_layout.addWidget(self.conn_table)
        self.conn_tab.setLayout(conn_layout)
        
        # System logs tab
        self.system_tab = QWidget()
        system_layout = QVBoxLayout()
        
        # System logs table
        self.system_table = QTableWidget(0, 4)  # Rows will be added dynamically
        self.system_table.setHorizontalHeaderLabels([
            "Time", "Level", "Event", "Details"
        ])
        self.setup_table(self.system_table)
        system_layout.addWidget(self.system_table)
        self.system_tab.setLayout(system_layout)
        
        # Add tabs to the tab widget
        self.tab_widget.addTab(self.conn_tab, "Connection Logs")
        self.tab_widget.addTab(self.system_tab, "System Events")
        
        # Add tab widget to main layout
        layout.addWidget(self.tab_widget)
        
        # Buttons layout
        button_layout = QHBoxLayout()
        
        # Clear button
        self.clear_btn = QPushButton("Clear Display")
        self.clear_btn.clicked.connect(self._clear_display)
        button_layout.addWidget(self.clear_btn)
        
        # Export button (placeholder for now)
        self.export_btn = QPushButton("Export Logs")
        self.export_btn.clicked.connect(self._export_logs)
        button_layout.addWidget(self.export_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)

    def setup_table(self, table):
        """Configure a table widget with common settings"""
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
        table.setFont(QFont("Sans", 9))
        
        # Style
        table.setStyleSheet("""
            QTableWidget {
                gridline-color: #d0d0d0;
                selection-background-color: #0078d7;
                selection-color: white;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 4px;
                font-weight: bold;
                border: 1px solid #d0d0d0;
            }
        """)
        
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
        elif not enabled and self.updater:
            self.updater.running = False
    
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
    
    def _add_connection_log_to_table(self, log):
        """Add a connection log entry to the table"""
        # Insert a new row at the top
        self.conn_table.insertRow(0)
        
        # Format time
        timestamp = log.get('timestamp', 0)
        time_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # Get log details
        src = f"{log.get('src_ip', '')}:{log.get('src_port', '')}"
        dst = f"{log.get('dst_ip', '')}:{log.get('dst_port', '')}"
        protocol = log.get('protocol', '')
        action = log.get('action', '')
        details = str(log.get('details', ''))
        
        # Add items to the table
        self.conn_table.setItem(0, 0, QTableWidgetItem(time_str))
        self.conn_table.setItem(0, 1, QTableWidgetItem(src))
        self.conn_table.setItem(0, 2, QTableWidgetItem(dst))
        self.conn_table.setItem(0, 3, QTableWidgetItem(protocol))
        self.conn_table.setItem(0, 4, QTableWidgetItem(action))
        self.conn_table.setItem(0, 5, QTableWidgetItem(details))
        
        # Color based on action
        if action == "BLOCK":
            for col in range(6):
                item = self.conn_table.item(0, col)
                item.setForeground(QBrush(QColor(255, 80, 80)))  # Red text for blocked
                item.setFont(QFont("Sans", 9, QFont.Bold))  # Bold for emphasis
    
    def _add_system_log_to_table(self, log):
        """Add a system log entry to the table"""
        # Insert a new row at the top
        self.system_table.insertRow(0)
        
        # Format time
        timestamp = log.get('timestamp', 0)
        time_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # Get log details
        level = log.get('level', 'INFO')
        event = log.get('event', '')
        details = str(log.get('details', ''))
        
        # Add items to the table
        self.system_table.setItem(0, 0, QTableWidgetItem(time_str))
        self.system_table.setItem(0, 1, QTableWidgetItem(level))
        self.system_table.setItem(0, 2, QTableWidgetItem(event))
        self.system_table.setItem(0, 3, QTableWidgetItem(details))
        
        # Color based on level
        color = QColor(0, 0, 0)  # Default black
        if level == "ERROR":
            color = QColor(255, 80, 80)  # Red
        elif level == "WARNING":
            color = QColor(255, 160, 10)  # Orange
            
        for col in range(4):
            item = self.system_table.item(0, col)
            item.setForeground(QBrush(color))
            if level == "ERROR":
                item.setFont(QFont("Sans", 9, QFont.Bold))  # Bold for errors
    
    def _export_logs(self):
        """Export logs to a file"""
        # This would be implemented to export logs to a CSV file
        pass
    
    def _clear_display(self):
        """Clear the display"""
        self.conn_table.setRowCount(0)
        self.system_table.setRowCount(0)
    
    def closeEvent(self, event):
        """Clean up threads when closing"""
        if self.updater:
            self.updater.stop()
        super().closeEvent(event)
    
    def sizeHint(self):
        return QSize(800, 600)