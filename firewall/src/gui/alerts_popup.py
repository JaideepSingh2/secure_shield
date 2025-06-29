from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
                           QLabel, QTextEdit, QSizePolicy, QApplication)
from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QFont, QIcon

class AlertPopup(QDialog):
    """Popup dialog for displaying firewall alerts"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Firewall Alert")
        self.setWindowFlags(Qt.Tool | Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._init_ui()
        
    def _init_ui(self):
        # Main layout with border styling
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        self.title_label = QLabel("🔒 Firewall Alert")
        self.title_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.title_label.setStyleSheet("color: white;")
        
        # Close button
        self.close_button = QPushButton("×")
        self.close_button.setFixedSize(20, 20)
        self.close_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: white;
                border: none;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 30);
            }
        """)
        self.close_button.clicked.connect(self.close)
        
        # Title bar layout
        title_layout = QHBoxLayout()
        title_layout.addWidget(self.title_label)
        title_layout.addStretch()
        title_layout.addWidget(self.close_button)
        self.main_layout.addLayout(title_layout)
        
        # Message
        self.message_label = QLabel()
        self.message_label.setWordWrap(True)
        self.message_label.setStyleSheet("color: white;")
        self.message_label.setFont(QFont("Arial", 10))
        self.main_layout.addWidget(self.message_label)
        
        # Details
        self.details_edit = QTextEdit()
        self.details_edit.setReadOnly(True)
        self.details_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.details_edit.setFixedHeight(80)
        self.details_edit.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 50);
                color: white;
                border: 1px solid rgba(255, 255, 255, 30);
            }
        """)
        self.main_layout.addWidget(self.details_edit)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Dismiss button
        self.dismiss_button = QPushButton("Dismiss")
        self.dismiss_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 255, 255, 20);
                color: white;
                border: 1px solid rgba(255, 255, 255, 30);
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 30);
            }
        """)
        self.dismiss_button.clicked.connect(self.close)
        button_layout.addWidget(self.dismiss_button)
        
        self.main_layout.addLayout(button_layout)
        
        # Set the main layout with custom styling
        self.setLayout(self.main_layout)
        
        # Style the dialog
        self.setStyleSheet("""
            AlertPopup {
                background-color: rgba(40, 40, 40, 240);
                border-radius: 10px;
                border: 1px solid rgba(255, 255, 255, 30);
            }
        """)
        
        # Timer for auto-dismiss
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.close)
        
    def show_alert(self, message, details=None, timeout=10000):
        """Show an alert with message and optional details"""
        self.message_label.setText(message)
        
        if details:
            if isinstance(details, dict):
                # Format dictionary for display
                details_str = "\n".join(f"{k}: {v}" for k, v in details.items())
                self.details_edit.setText(details_str)
            else:
                self.details_edit.setText(str(details))
            self.details_edit.show()
        else:
            self.details_edit.hide()
        
        # Position in bottom right of screen
        screen_geometry = QApplication.desktop().availableGeometry()
        self.setGeometry(
            screen_geometry.width() - self.width() - 20,
            screen_geometry.height() - self.height() - 60,
            300,
            self.sizeHint().height()
        )
        
        # Start timer
        if timeout > 0:
            self.timer.start(timeout)
            
        # Show the alert
        self.show()
        self.raise_()
        self.activateWindow()
        
    def sizeHint(self):
        """Return a sensible size for the dialog"""
        return QSize(300, 200)