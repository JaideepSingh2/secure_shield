from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
                           QLabel, QTextEdit, QSizePolicy, QApplication, QFrame)
from PyQt5.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, QTimer, QTime
from PyQt5.QtGui import QFont, QIcon

class AlertPopup(QDialog):
    """Enhanced popup dialog for displaying firewall alerts with unified styling"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SecureShield Alert")
        self.setWindowFlags(Qt.Tool | Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._init_ui()
        
        # Animation for smooth appearance
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(300)
        self.animation.setEasingCurve(QEasingCurve.OutCubic)
        
    def _init_ui(self):
        # Main container with unified styling
        self.main_frame = QFrame()
        self.main_frame.setStyleSheet("""
            QFrame {
                background-color: #252526;
                border: 2px solid #007ACC;
                border-radius: 12px;
            }
        """)
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.main_frame)
        
        # Content layout
        content_layout = QVBoxLayout(self.main_frame)
        content_layout.setContentsMargins(20, 15, 20, 15)
        content_layout.setSpacing(12)
        
        # Title bar
        title_bar = QFrame()
        title_bar.setStyleSheet("QFrame { border: none; background-color: transparent; }")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(0, 0, 0, 0)
        
        # Alert icon and title
        self.title_label = QLabel("🛡️ SecureShield Alert")
        self.title_label.setStyleSheet("""
            QLabel {
                color: #007ACC;
                font-size: 14px;
                font-weight: bold;
                background-color: transparent;
            }
        """)
        title_layout.addWidget(self.title_label)
        
        title_layout.addStretch()
        
        # Close button
        self.close_button = QPushButton("✕")
        self.close_button.setFixedSize(24, 24)
        self.close_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #D4D4D4;
                border: none;
                font-size: 14px;
                font-weight: bold;
                border-radius: 12px;
            }
            QPushButton:hover {
                background-color: #F14C4C;
                color: white;
            }
        """)
        self.close_button.clicked.connect(self.close)
        title_layout.addWidget(self.close_button)
        
        content_layout.addWidget(title_bar)
        
        # Alert type indicator
        self.alert_type = QLabel("FIREWALL ALERT")
        self.alert_type.setStyleSheet("""
            QLabel {
                color: #F14C4C;
                font-size: 12px;
                font-weight: bold;
                background-color: transparent;
            }
        """)
        content_layout.addWidget(self.alert_type)
        
        # Message
        self.message_label = QLabel()
        self.message_label.setWordWrap(True)
        self.message_label.setStyleSheet("""
            QLabel {
                color: #D4D4D4;
                font-size: 11px;
                background-color: transparent;
                padding: 5px 0px;
            }
        """)
        content_layout.addWidget(self.message_label)
        
        # Details container
        self.details_frame = QFrame()
        self.details_frame.setStyleSheet("""
            QFrame {
                background-color: #1E1E1E;
                border: 1px solid #454545;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        details_layout = QVBoxLayout(self.details_frame)
        details_layout.setContentsMargins(8, 8, 8, 8)
        
        # Details text
        self.details_edit = QTextEdit()
        self.details_edit.setReadOnly(True)
        self.details_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.details_edit.setFixedHeight(80)
        self.details_edit.setStyleSheet("""
            QTextEdit {
                background-color: transparent;
                color: #A0A0A0;
                border: none;
                font-size: 10px;
                font-family: "Courier New", monospace;
            }
        """)
        details_layout.addWidget(self.details_edit)
        
        content_layout.addWidget(self.details_frame)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 10, 0, 0)
        
        # View Rules button
        self.view_rules_btn = QPushButton("View Rules")
        self.view_rules_btn.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1F8AD2;
            }
        """)
        button_layout.addWidget(self.view_rules_btn)
        
        # Dismiss button
        self.dismiss_button = QPushButton("Dismiss")
        self.dismiss_button.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: #D4D4D4;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #454545;
            }
        """)
        self.dismiss_button.clicked.connect(self.close)
        button_layout.addWidget(self.dismiss_button)
        
        content_layout.addLayout(button_layout)
        
        # Timer for auto-dismiss
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.close)
        
    def show_alert(self, message, details=None, alert_type="BLOCKED CONNECTION", timeout=10000):
        """Show an alert with message and optional details"""
        # Set alert type and styling based on type
        self.alert_type.setText(alert_type)
        if "BLOCKED" in alert_type.upper():
            self.alert_type.setStyleSheet("""
                QLabel {
                    color: #F14C4C;
                    font-size: 12px;
                    font-weight: bold;
                    background-color: transparent;
                }
            """)
            self.title_label.setText("🚫 Connection Blocked")
        elif "ALLOWED" in alert_type.upper():
            self.alert_type.setStyleSheet("""
                QLabel {
                    color: #6A9955;
                    font-size: 12px;
                    font-weight: bold;
                    background-color: transparent;
                }
            """)
            self.title_label.setText("✅ Connection Allowed")
        elif "SYSTEM" in alert_type.upper():
            self.alert_type.setStyleSheet("""
                QLabel {
                    color: #D7BA7D;
                    font-size: 12px;
                    font-weight: bold;
                    background-color: transparent;
                }
            """)
            self.title_label.setText("⚙️ System Event")
        
        self.message_label.setText(message)
        
        if details:
            if isinstance(details, dict):
                # Format dictionary for display with better spacing
                details_str = "\n".join(f"{k:12}: {v}" for k, v in details.items())
                self.details_edit.setText(details_str)
            else:
                self.details_edit.setText(str(details))
            self.details_frame.show()
        else:
            self.details_frame.hide()
        
        # Position in bottom right of screen
        screen_geometry = QApplication.desktop().availableGeometry()
        dialog_width = 320
        dialog_height = self.sizeHint().height()
        
        self.setGeometry(
            screen_geometry.width() - dialog_width - 20,
            screen_geometry.height() - dialog_height - 80,
            dialog_width,
            dialog_height
        )
        
        # Animate appearance
        self.setWindowOpacity(0.0)
        self.show()
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(0.95)
        self.animation.start()
        
        # Start timer for auto-dismiss
        if timeout > 0:
            self.timer.start(timeout)
            
        # Raise and activate
        self.raise_()
        self.activateWindow()
    
    def show_blocked_connection(self, src_ip, dst_ip, dst_port, protocol):
        """Show a blocked connection alert"""
        message = f"Blocked connection attempt from {src_ip} to {dst_ip}:{dst_port}"
        details = {
            "Source IP": src_ip,
            "Destination": f"{dst_ip}:{dst_port}",
            "Protocol": protocol,
            "Action": "BLOCKED",
            "Time": QTime.currentTime().toString("hh:mm:ss")
        }
        self.show_alert(message, details, "BLOCKED CONNECTION")
    
    def show_system_event(self, event_type, description):
        """Show a system event alert"""
        message = f"System event: {description}"
        details = {
            "Event Type": event_type,
            "Description": description,
            "Time": QTime.currentTime().toString("hh:mm:ss")
        }
        self.show_alert(message, details, "SYSTEM EVENT")
        
    def closeEvent(self, event):
        """Handle close event with animation"""
        self.timer.stop()
        super().closeEvent(event)
        
    def sizeHint(self):
        """Return a sensible size for the dialog"""
        return QSize(320, 220)