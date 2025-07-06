from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QPushButton, 
                           QDialog, QFormLayout, QLineEdit, QComboBox, QTableWidgetItem,
                           QHeaderView, QCheckBox, QLabel, QMessageBox, QSpinBox, QFrame,
                           QTabWidget)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

class RuleDialog(QDialog):
    """Dialog for creating or editing a firewall rule - unified styling"""
    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.rule = rule or {}
        self.setWindowTitle("Edit Rule" if rule else "Add Rule")
        self.resize(500, 600)
        self.setStyleSheet("""
            QDialog {
                background-color: #1E1E1E;
                color: #D4D4D4;
            }
        """)
        self._init_ui()
        
    def _init_ui(self):
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        # Header section
        header_frame = QFrame()
        header_frame.setStyleSheet("QFrame { border: none; background-color: transparent; }")
        header_layout = QVBoxLayout(header_frame)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        title = QLabel("Edit Rule" if self.rule else "Add New Rule")
        title.setObjectName("title")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #007ACC; margin-bottom: 10px;")
        header_layout.addWidget(title)
        
        subtitle = QLabel("Configure firewall rule parameters")
        subtitle.setObjectName("info")
        subtitle.setStyleSheet("color: #A0A0A0; font-size: 10px;")
        header_layout.addWidget(subtitle)
        
        main_layout.addWidget(header_frame)
        
        # Form container
        form_container = QFrame()
        form_container.setStyleSheet("""
            QFrame {
                background-color: #252526;
                border: 1px solid #454545;
                border-radius: 8px;
                padding: 20px;
            }
        """)
        form_layout = QFormLayout(form_container)
        form_layout.setSpacing(12)
        
        # Rule name
        self.name_edit = QLineEdit(self.rule.get('name', ''))
        self.name_edit.setPlaceholderText("Enter a descriptive rule name")
        form_layout.addRow(self._create_label("Rule Name:"), self.name_edit)
        
        # Source IP
        self.src_ip_edit = QLineEdit(self.rule.get('src_ip', ''))
        self.src_ip_edit.setPlaceholderText("e.g. 192.168.1.10 or 192.168.1.0/24 or * for any")
        form_layout.addRow(self._create_label("Source IP:"), self.src_ip_edit)
        
        # Destination IP
        self.dst_ip_edit = QLineEdit(self.rule.get('dst_ip', ''))
        self.dst_ip_edit.setPlaceholderText("e.g. 8.8.8.8 or 10.0.0.0/8 or * for any")
        form_layout.addRow(self._create_label("Destination IP:"), self.dst_ip_edit)
        
        # Protocol
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(['ANY', 'TCP', 'UDP', 'ICMP'])
        if 'protocol' in self.rule:
            index = self.protocol_combo.findText(self.rule['protocol'])
            if index >= 0:
                self.protocol_combo.setCurrentIndex(index)
        form_layout.addRow(self._create_label("Protocol:"), self.protocol_combo)
        
        # Source Port
        self.src_port_edit = QLineEdit(str(self.rule.get('src_port', '')))
        self.src_port_edit.setPlaceholderText("e.g. 1024 or 1024-2048 or * for any")
        form_layout.addRow(self._create_label("Source Port:"), self.src_port_edit)
        
        # Destination Port
        self.dst_port_edit = QLineEdit(str(self.rule.get('dst_port', '')))
        self.dst_port_edit.setPlaceholderText("e.g. 80 or 80,443 or * for any")
        form_layout.addRow(self._create_label("Destination Port:"), self.dst_port_edit)
        
        # Action
        self.action_combo = QComboBox()
        self.action_combo.addItems(['ALLOW', 'BLOCK'])
        if 'action' in self.rule:
            index = self.action_combo.findText(self.rule['action'])
            if index >= 0:
                self.action_combo.setCurrentIndex(index)
        form_layout.addRow(self._create_label("Action:"), self.action_combo)
        
        # Priority
        self.priority_spin = QSpinBox()
        self.priority_spin.setRange(1, 100)
        self.priority_spin.setValue(self.rule.get('priority', 50))
        form_layout.addRow(self._create_label("Priority:"), self.priority_spin)
        
        # Enabled
        self.enabled_checkbox = QCheckBox("Enable this rule")
        self.enabled_checkbox.setChecked(self.rule.get('enabled', True))
        form_layout.addRow("", self.enabled_checkbox)
        
        # Description
        self.description_edit = QLineEdit(self.rule.get('description', ''))
        self.description_edit.setPlaceholderText("Optional description for this rule")
        form_layout.addRow(self._create_label("Description:"), self.description_edit)
        
        main_layout.addWidget(form_container)
        
        # Buttons
        button_frame = QFrame()
        button_frame.setStyleSheet("QFrame { border: none; background-color: transparent; }")
        button_layout = QHBoxLayout(button_frame)
        button_layout.setContentsMargins(0, 20, 0, 0)
        
        save_button = QPushButton("Save Rule")
        save_button.setObjectName("success")
        save_button.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #1F8AD2;
            }
        """)
        save_button.clicked.connect(self.accept)
        button_layout.addWidget(save_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("secondary")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        main_layout.addWidget(button_frame)
        
        self.setLayout(main_layout)
    
    def _create_label(self, text):
        """Create a styled label for form fields"""
        label = QLabel(text)
        label.setStyleSheet("""
            QLabel {
                color: #D4D4D4;
                font-weight: bold;
                font-size: 11px;
            }
        """)
        return label
        
    def get_rule(self):
        """Get the rule data from the form"""
        rule = {
            'name': self.name_edit.text(),
            'protocol': self.protocol_combo.currentText(),
            'action': self.action_combo.currentText(),
            'priority': self.priority_spin.value(),
            'enabled': self.enabled_checkbox.isChecked(),
            'description': self.description_edit.text()
        }
        
        # Add optional fields only if they contain data
        if self.src_ip_edit.text():
            rule['src_ip'] = self.src_ip_edit.text()
        
        if self.dst_ip_edit.text():
            rule['dst_ip'] = self.dst_ip_edit.text()
        
        if self.src_port_edit.text():
            rule['src_port'] = self.src_port_edit.text()
        
        if self.dst_port_edit.text():
            rule['dst_port'] = self.dst_port_edit.text()
            
        # Preserve the original ID if we're editing
        if 'id' in self.rule:
            rule['id'] = self.rule['id']
            
        return rule

class RulesEditorWidget(QWidget):
    """Widget for editing firewall rules - unified styling"""
    rule_changed = pyqtSignal()
    
    def __init__(self, rule_manager=None, parent=None):
        super().__init__(parent)
        self.rule_manager = rule_manager
        self._init_ui()
        
        # Load rules if rule manager is provided
        if rule_manager:
            self.load_rules()
        
# ...existing code...

    def _init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Header section
        header_frame = QFrame()
        header_frame.setStyleSheet("QFrame { border: none; background-color: transparent; }")
        header_layout = QVBoxLayout(header_frame)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        title = QLabel("Firewall Rules")
        title.setObjectName("title")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #007ACC;")
        header_layout.addWidget(title)
        
        subtitle = QLabel("Manage firewall rules and access control policies")
        subtitle.setObjectName("info")
        subtitle.setStyleSheet("color: #A0A0A0; font-size: 11px; margin-bottom: 10px;")
        header_layout.addWidget(subtitle)
        
        layout.addWidget(header_frame)
        
        # Controls section
        controls_frame = QFrame()
        controls_frame.setStyleSheet("""
            QFrame {
                background-color: #252526;
                border: 1px solid #454545;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        controls_layout = QHBoxLayout(controls_frame)
        
        # Add rule button
        self.add_button = QPushButton("Add Rule")
        self.add_button.setObjectName("success")
        self.add_button.clicked.connect(self._add_rule)
        controls_layout.addWidget(self.add_button)
        
        # Edit rule button
        self.edit_button = QPushButton("Edit Rule")
        self.edit_button.setObjectName("secondary")
        self.edit_button.clicked.connect(self._edit_rule)
        controls_layout.addWidget(self.edit_button)
        
        # Delete rule button
        self.delete_button = QPushButton("Delete Rule")
        self.delete_button.setStyleSheet("""
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
        self.delete_button.clicked.connect(self._delete_rule)
        controls_layout.addWidget(self.delete_button)
        
        # Spacer
        controls_layout.addStretch()
        
        layout.addWidget(controls_frame)
        
        # **REWRITTEN TABLE SECTION** - Matching Activity Logs styling exactly
        # Create tab widget like Activity Logs (even though we only have one tab)
        self.rules_tab_widget = QTabWidget()
        self.rules_tab_widget.setStyleSheet("""
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
        
        # Rules tab content
        self.rules_tab = QWidget()
        rules_tab_layout = QVBoxLayout()
        rules_tab_layout.setContentsMargins(15, 15, 15, 15)
        
        # Create the rules table with EXACT same styling as Activity Logs
        self.rules_table = QTableWidget(0, 7)
        self.rules_table.setHorizontalHeaderLabels([
            "Name", "Source IP", "Destination IP", "Protocol", "Ports", "Action", "Enabled"
        ])
        
        # Apply EXACT same table styling as Activity Logs
        self.rules_table.setStyleSheet("""
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
        
        # Configure table exactly like Activity Logs
        header = self.rules_table.horizontalHeader()
        for i in range(header.count()):
            header.setSectionResizeMode(i, QHeaderView.Stretch)
        
        # Set selection behavior exactly like Activity Logs
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.rules_table.setSelectionMode(QTableWidget.SingleSelection)
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setSortingEnabled(False)  # Disable sorting like Activity Logs
        
        # Set font exactly like Activity Logs
        self.rules_table.setFont(QFont("Segoe UI", 10))
        
        # Add table to rules tab layout
        rules_tab_layout.addWidget(self.rules_table)
        self.rules_tab.setLayout(rules_tab_layout)
        
        # Add the tab to the tab widget
        self.rules_tab_widget.addTab(self.rules_tab, "🛡️ Firewall Rules")
        
        # Add tab widget to main layout
        layout.addWidget(self.rules_tab_widget)
        
        self.setLayout(layout)

    # ...existing code...    
    def load_rules(self):
        """Load rules from the rule manager"""
        if not self.rule_manager:
            return
        
        # Get all rules
        rules = self.rule_manager.rules
        
        # Update the table
        self._populate_table(rules)
    
    def _populate_table(self, rules):
        """Populate the table with rules"""
        self.rules_table.setRowCount(0)  # Clear existing rows
        
        # Add rules to table
        for row, rule in enumerate(rules):
            self.rules_table.insertRow(row)
            
            # Add rule data to table cells with enhanced styling
            name_item = QTableWidgetItem(rule.get('name', 'Unnamed'))
            name_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
            self.rules_table.setItem(row, 0, name_item)
            
            self.rules_table.setItem(row, 1, QTableWidgetItem(rule.get('src_ip', '*')))
            self.rules_table.setItem(row, 2, QTableWidgetItem(rule.get('dst_ip', '*')))
            self.rules_table.setItem(row, 3, QTableWidgetItem(rule.get('protocol', 'ANY')))
            
            # Combine ports for display
            ports = ""
            if 'src_port' in rule:
                ports += f"Src: {rule['src_port']}"
            if 'dst_port' in rule:
                if ports:
                    ports += ", "
                ports += f"Dst: {rule['dst_port']}"
            self.rules_table.setItem(row, 4, QTableWidgetItem(ports or '*'))
            
            # Action with color coding
            action_item = QTableWidgetItem(rule.get('action', 'ALLOW'))
            if rule.get('action') == 'BLOCK':
                action_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
            self.rules_table.setItem(row, 5, action_item)
            
            # Enabled status
            enabled_item = QTableWidgetItem()
            enabled_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            enabled_item.setCheckState(Qt.Checked if rule.get('enabled', True) else Qt.Unchecked)
            self.rules_table.setItem(row, 6, enabled_item)
            
            # Store the rule ID as item data
            if 'id' in rule:
                self.rules_table.item(row, 0).setData(Qt.UserRole, rule['id'])
    
    def _get_selected_rule_id(self):
        """Get the ID of the selected rule"""
        selected_rows = self.rules_table.selectedItems()
        if not selected_rows:
            return None
            
        # Get the ID from the first column of selected row
        row = selected_rows[0].row()
        return self.rules_table.item(row, 0).data(Qt.UserRole)
    
    def _add_rule(self):
        """Open dialog to add a new rule"""
        if not self.rule_manager:
            QMessageBox.warning(self, "Error", "Rule manager not initialized")
            return
            
        dialog = RuleDialog(self)
        if dialog.exec_():
            # Get the new rule data
            rule = dialog.get_rule()
            
            # Add the rule using rule manager
            rule_id = self.rule_manager.add_rule(rule)
            
            # Reload the table
            self.load_rules()
            
            # Emit signal
            self.rule_changed.emit()
    
    def _edit_rule(self):
        """Open dialog to edit the selected rule"""
        if not self.rule_manager:
            QMessageBox.warning(self, "Error", "Rule manager not initialized")
            return
            
        rule_id = self._get_selected_rule_id()
        if not rule_id:
            QMessageBox.information(self, "Select Rule", "Please select a rule to edit")
            return
            
        # Get the full rule data
        rule = self.rule_manager.get_rule(rule_id)
        if not rule:
            QMessageBox.warning(self, "Error", "Rule not found")
            return
            
        # Open edit dialog
        dialog = RuleDialog(self, rule)
        if dialog.exec_():
            # Get the updated rule data
            updated_rule = dialog.get_rule()
            
            # Update the rule
            self.rule_manager.update_rule(rule_id, updated_rule)
            
            # Reload the table
            self.load_rules()
            
            # Emit signal
            self.rule_changed.emit()
    
    def _delete_rule(self):
        """Delete the selected rule"""
        if not self.rule_manager:
            QMessageBox.warning(self, "Error", "Rule manager not initialized")
            return
            
        rule_id = self._get_selected_rule_id()
        if not rule_id:
            QMessageBox.information(self, "Select Rule", "Please select a rule to delete")
            return
            
        # Confirm deletion
        reply = QMessageBox.question(self, "Confirm Deletion", 
                                    "Are you sure you want to delete this rule?",
                                    QMessageBox.Yes | QMessageBox.No)
                                    
        if reply == QMessageBox.Yes:
            # Delete the rule
            self.rule_manager.delete_rule(rule_id)
            
            # Reload the table
            self.load_rules()
            
            # Emit signal
            self.rule_changed.emit()