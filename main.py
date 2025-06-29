import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import threading
import signal
from datetime import datetime
from PIL import Image, ImageTk
import sqlite3
import csv

# Color scheme
COLORS = {
    "bg_dark": "#1E1E1E",         # Dark background
    "bg_medium": "#252526",        # Medium background for panels
    "bg_light": "#333333",         # Lighter background for inputs
    "accent": "#007ACC",           # Accent color (blue)
    "accent_hover": "#1F8AD2",     # Accent hover
    "success": "#6A9955",          # Success/safe color
    "warning": "#D7BA7D",          # Warning color
    "error": "#F14C4C",            # Error/threat color
    "text": "#D4D4D4",             # Primary text
    "text_dim": "#A0A0A0",         # Secondary text
    "border": "#454545"            # Border color
}

# Global variables
process_rtm = None

class AntivirusApp:
    """Main application class for SecureShield Antivirus"""
    def __init__(self, root):
        self.root = root
        self.root.title("SecureShield Antivirus")
        self.root.geometry("1440x900")
        self.root.configure(bg=COLORS["bg_dark"])
        self.root.minsize(1200, 800)  # Set minimum size
        
        # Paths to executables - Move this initialization earlier
        self.engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antivirus", "engine")
        self.rtm_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antivirus", "rtm")
        
        # Make executables... executable
        for path in [self.engine_path, self.rtm_path]:
            if os.path.exists(path) and not os.access(path, os.X_OK):
                os.chmod(path, 0o755)
        
        # Database initialization
        self.db_manager = DatabaseManager()
        
        # Configure ttk styles
        self.style_manager = StyleManager()
        self.style_manager.setup_styles()
        
        # Set up the main layout
        self.layout_manager = LayoutManager(self.root, self)
        self.layout_manager.setup_layout()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            
    def get_timestamp(self):
        """Get a formatted timestamp for logging"""
        return datetime.now().strftime("%H:%M:%S")
    
    def on_closing(self):
        """Handle window closing event"""
        global process_rtm
        
        # Ask for confirmation if RTM is active
        if process_rtm and process_rtm.poll() is None:
            if not messagebox.askokcancel("Exit", "Real-time monitoring is active. Exit anyway?"):
                return
        
        # Terminate RTM process if running
        if process_rtm and process_rtm.poll() is None:
            process_rtm.terminate()
            try:
                process_rtm.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process_rtm.kill()
        
        # Close the database connection
        self.db_manager.close()
        
        # Close the window
        self.root.destroy()


class DatabaseManager:
    """Manages database operations for the antivirus application"""
    def __init__(self):
        self.db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antivirus", "secureshield.db")
        self.conn = self._create_connection()
        self._initialize_database()
    
    def _create_connection(self):
        """Create a database connection to the SQLite database"""
        try:
            return sqlite3.connect(self.db_path)
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None
    
# Add these methods to the DatabaseManager class

    def _initialize_database(self):
        """Create necessary tables if they don't exist"""
        if not self.conn:
            return
        
        try:
            cursor = self.conn.cursor()
            
            # Create exceptions table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS exceptions (
                id INTEGER PRIMARY KEY,
                file_path TEXT NOT NULL UNIQUE,
                reason TEXT,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Create scan history table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY,
                scan_type TEXT NOT NULL,
                path TEXT NOT NULL,
                threats_found INTEGER,
                date_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Create threat history table - NEW!
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY,
                file_path TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                action_taken TEXT,
                date_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")

    def add_threat_history(self, file_path, threat_type, action_taken="No action"):
        """Add a detected threat to history"""
        if not self.conn:
            return False
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO threat_history (file_path, threat_type, action_taken) VALUES (?, ?, ?)",
                (file_path, threat_type, action_taken)
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error adding threat history: {e}")
            return False

    def get_threat_history(self, limit=50):
        """Get recent threat history"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT date_detected, file_path, threat_type, action_taken FROM threat_history ORDER BY date_detected DESC LIMIT ?",
                (limit,)
            )
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error getting threat history: {e}")
            return []

    def get_filtered_scan_history(self, scan_type=None, start_date=None, end_date=None, limit=50):
        """Get filtered scan history"""
        if not self.conn:
            return []
        
        try:
            query = "SELECT scan_type, path, threats_found, date_scanned FROM scan_history"
            conditions = []
            params = []
            
            if scan_type:
                conditions.append("scan_type = ?")
                params.append(scan_type)
            
            if start_date:
                conditions.append("date_scanned >= ?")
                params.append(f"{start_date} 00:00:00")
            
            if end_date:
                conditions.append("date_scanned <= ?")
                params.append(f"{end_date} 23:59:59")
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY date_scanned DESC LIMIT ?"
            params.append(limit)
            
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error getting filtered scan history: {e}")
            return []

    def clear_scan_history(self):
        """Clear all scan history"""
        if not self.conn:
            return False
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM scan_history")
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error clearing scan history: {e}")
            return False

    def clear_threat_history(self):
        """Clear all threat history"""
        if not self.conn:
            return False
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM threat_history")
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error clearing threat history: {e}")
            return False
        
    def add_exception(self, file_path, reason=None):
        """Add a file to exceptions"""
        if not self.conn:
            return False
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO exceptions (file_path, reason) VALUES (?, ?)",
                (file_path, reason)
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error adding exception: {e}")
            return False
    
    def remove_exception(self, file_path):
        """Remove a file from exceptions"""
        if not self.conn:
            return False
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM exceptions WHERE file_path = ?", (file_path,))
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            print(f"Error removing exception: {e}")
            return False
    
    def get_all_exceptions(self):
        """Get all file exceptions"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT file_path, reason, date_added FROM exceptions ORDER BY date_added DESC")
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error getting exceptions: {e}")
            return []
    
    def is_file_excepted(self, file_path):
        """Check if a file is in exceptions"""
        if not self.conn:
            return False
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1 FROM exceptions WHERE file_path = ?", (file_path,))
            return cursor.fetchone() is not None
        except sqlite3.Error as e:
            print(f"Error checking exception: {e}")
            return False
    
    def add_scan_history(self, scan_type, path, threats_found):
        """Add a scan to history"""
        if not self.conn:
            return False
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO scan_history (scan_type, path, threats_found) VALUES (?, ?, ?)",
                (scan_type, path, threats_found)
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error adding scan history: {e}")
            return False
    
    def get_scan_history(self, limit=50):
        """Get recent scan history"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT scan_type, path, threats_found, date_scanned FROM scan_history ORDER BY date_scanned DESC LIMIT ?",
                (limit,)
            )
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error getting scan history: {e}")
            return []
    
    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()

class StyleManager:
    """Manages application styling and themes"""
    def __init__(self):
        self.style = ttk.Style()
    
    def setup_styles(self):
        """Configure ttk styles for the application"""
        self.style.theme_use('default')
        
        # Configure colors
        self.style.configure('TFrame', background=COLORS["bg_dark"])
        self.style.configure('TSeparator', background=COLORS["bg_dark"])
        
        # Button styles
        self.style.configure('Primary.TButton', 
                            background=COLORS["accent"],
                            foreground='white', 
                            font=('Segoe UI', 10),
                            padding=10)
        
        self.style.map('Primary.TButton',
                      background=[('active', COLORS["accent_hover"]),
                                 ('disabled', COLORS["bg_light"])])
        
        self.style.configure('Secondary.TButton', 
                            background=COLORS["bg_light"],
                            foreground=COLORS["text"], 
                            font=('Segoe UI', 10),
                            padding=10)
        
        self.style.map('Secondary.TButton',
                      background=[('active', COLORS["bg_medium"])],
                      foreground=[('active', COLORS["text"])])
        
        # Label styles
        self.style.configure('Title.TLabel', 
                            background=COLORS["bg_dark"],
                            foreground=COLORS["accent"], 
                            font=('Segoe UI', 18, 'bold'))
        
        self.style.configure('Subtitle.TLabel', 
                            background=COLORS["bg_dark"],
                            foreground=COLORS["text"], 
                            font=('Segoe UI', 12))
        
        self.style.configure('Info.TLabel', 
                            background=COLORS["bg_dark"],
                            foreground=COLORS["text_dim"], 
                            font=('Segoe UI', 10))
        
        # Entry style
        self.style.configure('TEntry', 
                            fieldbackground=COLORS["bg_light"],
                            foreground=COLORS["text"],
                            insertcolor=COLORS["text"])
        
        # Separator style
        self.style.configure('TSeparator', background=COLORS["border"])
        
        # Progressbar style
        self.style.configure("TProgressbar", 
                           troughcolor=COLORS["bg_light"],
                           background=COLORS["accent"])
        
        # Treeview style
        self.style.configure("Treeview",
                           background=COLORS["bg_medium"],
                           foreground=COLORS["text"],
                           rowheight=25,
                           fieldbackground=COLORS["bg_medium"])
        
        self.style.map('Treeview', 
                     background=[('selected', COLORS["accent"])],
                     foreground=[('selected', 'white')])
        
        # Checkbutton style
        self.style.configure('TCheckbutton',
                           background=COLORS["bg_dark"],
                           foreground=COLORS["text"])
        
        self.style.map('TCheckbutton',
                     background=[('active', COLORS["bg_dark"])])
        
class LayoutManager:
    """Manages the application layout and UI components"""
    def __init__(self, root, app):
        self.root = root
        self.app = app
        self.sidebar = None
        self.content_area = None
        self.rtm_status_var = tk.StringVar(value="Inactive")
        self.rtm_status_indicator = None
        self.output_text_rtm = None
        self.logs_container = None
        
        # Initialize scan and RTM managers
        self.scan_manager = ScanManager(app)
        self.rtm_manager = RTMManager(app)
    
    def setup_layout(self):
        """Set up the main layout with sidebar and content area"""
        # Main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left sidebar (fixed width)
        self.sidebar = ttk.Frame(self.main_container, width=250, style='TFrame')
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)  # Prevent resizing
        
        # Content area (flexible width)
        self.content_area = ttk.Frame(self.main_container)
        self.content_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add sidebar elements
        self.setup_sidebar()
        
        # Add content area elements
        self.setup_content_area()
    
    def setup_sidebar(self):
        """Set up the sidebar with logo and navigation"""
        # Logo frame
        logo_frame = ttk.Frame(self.sidebar)
        logo_frame.pack(fill=tk.X, padx=20, pady=30)
        
        # Try to load logo, use text as fallback
        try:
            # Using PIL to handle the logo image
            logo_img = Image.open("antivirus/images/logo.png")
            logo_img = logo_img.resize((180, 60), Image.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(logo_img)
            logo_label = ttk.Label(logo_frame, image=self.logo_photo, background=COLORS["bg_dark"])
            logo_label.pack()
        except Exception as e:
            print(f"Error loading logo: {e}")
            # Fallback to text logo
            logo_label = ttk.Label(logo_frame, text="SecureShield", 
                                style='Title.TLabel', background=COLORS["bg_dark"])
            logo_label.pack()
        
        # Navigation options
        nav_frame = ttk.Frame(self.sidebar)
        nav_frame.pack(fill=tk.X, padx=10, pady=20)
        
        # Sidebar buttons
        btn_home = tk.Button(nav_frame, text="Home", 
                          font=("Segoe UI", 11), 
                          bg=COLORS["accent"], fg="white",
                          activebackground=COLORS["accent_hover"],
                          activeforeground="white",
                          borderwidth=0, padx=20, pady=10,
                          command=lambda: None)  # Already on home
        btn_home.pack(fill=tk.X, pady=5)
        
        btn_password = tk.Button(nav_frame, text="Password Manager", 
                              font=("Segoe UI", 11), 
                              bg=COLORS["bg_light"], fg=COLORS["text"],
                              activebackground=COLORS["bg_medium"],
                              activeforeground=COLORS["text"],
                              borderwidth=0, padx=20, pady=10,
                              command=self.scan_manager.open_password_manager)
        btn_password.pack(fill=tk.X, pady=5)
        
        # ADD THIS SECTION FOR STATUS DISPLAY
        # Separator
        ttk.Separator(self.sidebar, orient='horizontal').pack(fill=tk.X, padx=20, pady=15)
        
        # Status display
        status_frame = ttk.Frame(self.sidebar)
        status_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(status_frame, text="Protection Status", style='Subtitle.TLabel').pack(anchor=tk.W)
        
        # RTM status indicator
        self.rtm_status_indicator = tk.Label(status_frame, textvariable=self.rtm_status_var,
                                        font=("Segoe UI", 12),
                                        fg=COLORS["error"], bg=COLORS["bg_dark"])
        self.rtm_status_indicator.pack(anchor=tk.W, pady=5)
        
        # Version info at bottom
        version_frame = ttk.Frame(self.sidebar)
        version_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=20)
        
        ttk.Label(version_frame, text="SecureShield v1.0", style='Info.TLabel').pack(side=tk.LEFT)

    def setup_content_area(self):
        """Set up the main content area"""
        # Header with welcome message
        header = ttk.Frame(self.content_area)
        header.pack(fill=tk.X, padx=30, pady=20)
        
        ttk.Label(header, text="Welcome to SecureShield", style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(header, text="Protect your system with advanced security features", 
                style='Subtitle.TLabel').pack(anchor=tk.W, pady=5)
        
        # Quick access buttons for History and Exceptions
        quick_access_frame = ttk.Frame(header)
        quick_access_frame.pack(side=tk.RIGHT)
        
        history_btn = ttk.Button(quick_access_frame, text="History", 
                              style="Secondary.TButton",
                              command=self.show_history_manager)
        history_btn.pack(side=tk.RIGHT, padx=5)
        
        exceptions_btn = ttk.Button(quick_access_frame, text="Exceptions", 
                                  style="Secondary.TButton",
                                  command=self.rtm_manager.show_exceptions_manager)
        exceptions_btn.pack(side=tk.RIGHT, padx=5)
        
        # Quick action buttons
        action_frame = ttk.Frame(self.content_area)
        action_frame.pack(fill=tk.X, padx=30, pady=10)
        
        # Use a grid layout for the action cards
        action_frame.columnconfigure(0, weight=1)
        action_frame.columnconfigure(1, weight=1)
        action_frame.columnconfigure(2, weight=1)
        
        # Scan File Card
        scan_file_frame = self.create_action_card(
            action_frame, "Scan File", 
            "Analyze individual files for threats",
            "scan_file.png", self.scan_manager.open_file_scanner)
        scan_file_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Scan Directory Card
        scan_dir_frame = self.create_action_card(
            action_frame, "Scan Directory", 
            "Perform deep scan on folders",
            "scan_folder.png", self.scan_manager.open_directory_scanner)
        scan_dir_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        # RTM Configuration Card
        rtm_frame = self.create_action_card(
            action_frame, "Real-Time Monitoring", 
            "Configure protection settings",
            "rtm_config.png", self.rtm_manager.show_rtm_config)
        rtm_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")
        
        # Separator
        ttk.Separator(self.content_area, orient='horizontal').pack(fill=tk.X, padx=30, pady=15)
        
        # RTM Logs Section (initially hidden)
        self.setup_rtm_logs_section()


    def show_history_manager(self):
        """Show the scan history window"""
        HistoryManagerWindow(self.app)

    def setup_rtm_logs_section(self):
        """Set up the RTM logs section (initially hidden)"""
        # Real-time Monitoring Logs Section
        self.logs_frame = ttk.Frame(self.content_area)
        self.logs_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=10)
        
        logs_header = ttk.Frame(self.logs_frame)
        logs_header.pack(fill=tk.X, pady=10)
        
        ttk.Label(logs_header, text="Real-Time Monitoring Logs", style='Title.TLabel').pack(side=tk.LEFT)
        
        # Button frame with Clear and Toggle buttons
        btn_frame = ttk.Frame(logs_header)
        btn_frame.pack(side=tk.RIGHT)
        
        # Clear logs button
        clear_btn = ttk.Button(
            btn_frame, text="Clear Logs", style="Secondary.TButton",
            command=self.clear_rtm_logs
        )
        clear_btn.pack(side=tk.RIGHT, padx=5)
        
        # Toggle logs visibility button
        self.toggle_btn = ttk.Button(
            btn_frame, text="Hide Logs", style="Secondary.TButton",
            command=self.toggle_rtm_logs_visibility
        )
        self.toggle_btn.pack(side=tk.RIGHT, padx=5)
        
        # Container for logs
        self.logs_container = ttk.Frame(self.logs_frame)
        self.logs_container.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create a Text widget with a scrollbar for logs
        self.output_text_rtm = tk.Text(self.logs_container, wrap='word',
                                    font=('Segoe UI', 10),
                                    bg=COLORS["bg_medium"],
                                    fg=COLORS["text"],
                                    border=0)
        self.output_text_rtm.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure tags for the RTM logs
        self.setup_text_tags()
        
        # Add welcome message to logs
        self.output_text_rtm.insert(tk.END, "SecureShield Real-Time Monitoring initialized.\n", "header")
        self.output_text_rtm.insert(tk.END, "Logs will appear here when monitoring is active.\n\n", "info")
        
        scrollbar = ttk.Scrollbar(self.logs_container, orient="vertical", command=self.output_text_rtm.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.output_text_rtm.config(yscrollcommand=scrollbar.set)
        
        # Initially hide the logs
        self.toggle_rtm_logs_visibility()
    
    def toggle_rtm_logs_visibility(self):
        """Toggle the visibility of RTM logs"""
        if self.logs_container.winfo_viewable():
            self.logs_container.pack_forget()
            self.toggle_btn.config(text="Show Logs")
        else:
            self.logs_container.pack(fill=tk.BOTH, expand=True, pady=10)
            self.toggle_btn.config(text="Hide Logs")
    
    def clear_rtm_logs(self):
        """Clear the RTM logs"""
        self.output_text_rtm.delete(1.0, tk.END)
        self.output_text_rtm.insert(tk.END, "Logs cleared.\n", "info")
    
    def setup_text_tags(self):
        """Configure tags for the RTM logs"""
        tags = {
            "safe": {"foreground": COLORS["success"], "font": ('Segoe UI', 11, 'bold')},
            "unsafe": {"foreground": COLORS["error"], "font": ('Segoe UI', 11, 'bold')},
            "unsafe_details": {"foreground": COLORS["warning"]},
            "detection": {"foreground": COLORS["error"]},
            "change": {"foreground": COLORS["warning"], "font": ('Segoe UI', 11, 'bold')},
            "error": {"foreground": COLORS["error"], "font": ('Segoe UI', 10, 'italic')},
            "header": {"foreground": COLORS["accent"], "font": ('Segoe UI', 11, 'bold')},
            "info": {"foreground": COLORS["text_dim"]},
            "scan_start": {"foreground": COLORS["accent"], "font": ('Segoe UI', 10)},
            "scan_complete": {"foreground": COLORS["success"], "font": ('Segoe UI', 10, 'bold')},
            "initial_scan": {"foreground": COLORS["text_dim"]},
            "monitoring": {"foreground": COLORS["accent"], "font": ('Segoe UI', 10, 'bold')},
            "normal": {"foreground": COLORS["text"]},
            "deletion": {"foreground": "#ff9999"},  # Light red
            "created": {"foreground": COLORS["success"], "font": ('Segoe UI', 10)},
            "deleted": {"foreground": COLORS["error"], "font": ('Segoe UI', 10)}
        }
        
        # Apply the tags to the text widget
        for tag_name, properties in tags.items():
            self.output_text_rtm.tag_configure(tag_name, **properties)
    
    def create_action_card(self, parent, title, description, icon_name, command):
        """Create an action card with icon, title, description, and button"""
        frame = ttk.Frame(parent, style='TFrame')
        frame.configure(borderwidth=1, relief=tk.SOLID)
        
        # Container for content with some padding
        inner_frame = ttk.Frame(frame)
        inner_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Try to load icon
        try:
            img = Image.open(f"antivirus/images/{icon_name}")
            img = img.resize((48, 48), Image.LANCZOS)
            icon = ImageTk.PhotoImage(img)
            icon_label = ttk.Label(inner_frame, image=icon, background=COLORS["bg_dark"])
            icon_label.image = icon  # Keep a reference
            icon_label.pack(anchor=tk.W, pady=(0, 10))
        except Exception as e:
            print(f"Error loading icon {icon_name}: {e}")
            # No icon fallback
        
        # Title and description
        ttk.Label(inner_frame, text=title, 
                style='Subtitle.TLabel', font=('Segoe UI', 14, 'bold')).pack(anchor=tk.W)
        
        ttk.Label(inner_frame, text=description, 
                style='Info.TLabel', wraplength=200).pack(anchor=tk.W, pady=10)
        
        # Button at bottom
        action_button = ttk.Button(inner_frame, text=f"Open {title}", 
                                 style="Primary.TButton", command=command)
        action_button.pack(anchor=tk.W, pady=(10, 0))
        
        return frame
    

class ScanManager:
    """Manages file and directory scanning operations"""
    def __init__(self, app):
        self.app = app
        self.engine_path = app.engine_path
    
    def open_file_scanner(self):
        """Open the file scanner dialog"""
        selected_file_path = filedialog.askopenfilename(parent=self.app.root)
        if selected_file_path:
            self.scan_file(selected_file_path)
    
    def open_directory_scanner(self):
        """Open the directory scanner dialog"""
        selected_dir_path = filedialog.askdirectory(parent=self.app.root)
        if selected_dir_path:
            self.scan_directory(selected_dir_path)
    
    def scan_file(self, selected_file_path):
        """Scan a single file for threats"""
        # Create scanning window
        scan_window = tk.Toplevel(self.app.root)
        scan_window.title("File Scan")
        scan_window.geometry("600x300")
        scan_window.configure(bg=COLORS["bg_dark"])
        scan_window.transient(self.app.root)  # Make it appear on top of root
        scan_window.focus_set()  # Set focus to this window
        scan_window.grab_set()   # Make it modal
        
        # Add content to the scan window
        ttk.Label(scan_window, text=f"Scanning: {os.path.basename(selected_file_path)}", 
                style='Title.TLabel').pack(padx=20, pady=20)
        
        # Path display
        path_frame = ttk.Frame(scan_window)
        path_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(path_frame, text="Path:", style='Subtitle.TLabel').pack(side=tk.LEFT)
        ttk.Label(path_frame, text=selected_file_path, style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        progress_frame = ttk.Frame(scan_window)
        progress_frame.pack(fill=tk.X, padx=20, pady=10)
        
        progress = ttk.Progressbar(progress_frame, orient="horizontal", length=500, mode="indeterminate")
        progress.pack(fill=tk.X)
        progress.start()
        
        # Status message
        status_var = tk.StringVar(value="Scanning file...")
        status_label = ttk.Label(scan_window, textvariable=status_var, style='Info.TLabel')
        status_label.pack(pady=10)
        
        # Button frame
        button_frame = ttk.Frame(scan_window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", style="Secondary.TButton",
                                command=lambda: self.close_window(scan_window))
        cancel_button.pack(side=tk.RIGHT)
        
        # Store scan results
        scan_results = {
            "threats_found": False,
            "file_threats": {},
            "detection_files": set(),
            "scan_logs": []
        }
        
        # Execute the scan in a separate thread
        threading.Thread(
            target=self._execute_scan_thread,
            args=(selected_file_path, scan_window, status_var, progress, scan_results, "file"),
            daemon=True
        ).start()
    
    def scan_directory(self, selected_dir_path):
        """Scan a directory for threats"""
        # Create scanning window
        scan_window = tk.Toplevel(self.app.root)
        scan_window.title("Directory Scan")
        scan_window.geometry("600x300")
        scan_window.configure(bg=COLORS["bg_dark"])
        scan_window.transient(self.app.root)  # Make it appear on top of root
        scan_window.focus_set()  # Set focus to this window
        scan_window.grab_set()   # Make it modal
        
        # Add content to the scan window
        ttk.Label(scan_window, text=f"Scanning Directory: {os.path.basename(selected_dir_path)}", 
                style='Title.TLabel').pack(padx=20, pady=20)
        
        # Path display
        path_frame = ttk.Frame(scan_window)
        path_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(path_frame, text="Path:", style='Subtitle.TLabel').pack(side=tk.LEFT)
        ttk.Label(path_frame, text=selected_dir_path, style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        progress_frame = ttk.Frame(scan_window)
        progress_frame.pack(fill=tk.X, padx=20, pady=10)
        
        progress = ttk.Progressbar(progress_frame, orient="horizontal", length=500, mode="indeterminate")
        progress.pack(fill=tk.X)
        progress.start()
        
        # Status message
        status_var = tk.StringVar(value="Scanning directory...")
        status_label = ttk.Label(scan_window, textvariable=status_var, style='Info.TLabel')
        status_label.pack(pady=10)
        
        # Current file being scanned
        current_file_var = tk.StringVar()
        current_file_label = ttk.Label(scan_window, textvariable=current_file_var, style='Info.TLabel')
        current_file_label.pack(pady=5)
        
        # Button frame
        button_frame = ttk.Frame(scan_window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", style="Secondary.TButton",
                                command=lambda: self.close_window(scan_window))
        cancel_button.pack(side=tk.RIGHT)
        
        # Store scan results
        scan_results = {
            "threats_found": False,
            "file_threats": {},
            "detection_files": set(),
            "scan_logs": []
        }
        
        # Execute the scan in a separate thread
        threading.Thread(
            target=self._execute_scan_thread,
            args=(selected_dir_path, scan_window, status_var, progress, scan_results, "directory", current_file_var),
            daemon=True
        ).start()
    
    def _execute_scan_thread(self, path, scan_window, status_var, progress, scan_results, scan_type, current_file_var=None):
        """Execute scan in a separate thread"""
        try:
            # Execute engine and capture output
            process = subprocess.Popen(
                [self.engine_path, path], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Read and process output
            while True:
                output_line = process.stdout.readline()
                if not output_line and process.poll() is not None:
                    break
                
                if output_line:
                    # Process the output line and store relevant information
                    self._process_scan_output(output_line, scan_results, scan_type)
                    
                    # Update current file being scanned for directory scan
                    if current_file_var and output_line.startswith("[R] FILE_SCANNING:"):
                        file_path = output_line[17:].strip()
                        scan_window.after(0, lambda: current_file_var.set(f"Scanning: {os.path.basename(file_path)}"))
            
            # Store log for detailed view later
            scan_results["scan_logs"].append(f"✅ Scan completed on {path}")
            
            # Add to scan history
            threats_count = len(scan_results["file_threats"])
            self.app.db_manager.add_scan_history(scan_type, path, threats_count)
            
            # Update UI when scan is complete
            scan_window.after(0, lambda: self._show_scan_results(path, scan_window, status_var, progress, scan_results, scan_type))
            
        except Exception as e:
            error_message = f"Error: {str(e)}"
            scan_results["scan_logs"].append(error_message)
            scan_window.after(0, lambda: status_var.set(error_message))
            scan_window.after(0, progress.stop)
    
    def _process_scan_output(self, output_line, scan_results, scan_type):
        """Process a line of output from the scanning engine"""
        # Add raw output to logs for detailed view
        scan_results["scan_logs"].append(output_line.strip())
        
        # Only process result lines that start with [R]
        if output_line.startswith("[R]"):
            # Parse result lines
            result_line = output_line[4:].strip()  # Remove "[R] " prefix
            parts = result_line.split(":", 3)  # Split by first 3 colons
            
            if len(parts) >= 1:
                if parts[0] == "DETECTION" and len(parts) >= 3:
                    detected_path = parts[2]
                    rule_name = parts[1]
                    
                    # Track this file and its threats
                    if detected_path not in scan_results["file_threats"]:
                        scan_results["file_threats"][detected_path] = []
                    scan_results["file_threats"][detected_path].append(rule_name)
                    scan_results["detection_files"].add(detected_path)
                    scan_results["threats_found"] = True
                
                elif parts[0] == "UNSAFE" and len(parts) >= 4:
                    unsafe_path = parts[1]
                    threats = parts[3]
                    
                    # Track this file
                    scan_results["detection_files"].add(unsafe_path)
                    scan_results["threats_found"] = True
                    
                    # Track threats
                    if unsafe_path not in scan_results["file_threats"]:
                        scan_results["file_threats"][unsafe_path] = threats.split(", ")
    
    def _show_scan_results(self, path, scan_window, status_var, progress, scan_results, scan_type):
        """Show scan results after scan completes"""
        # Stop the progress bar
        progress.stop()
        
        # Close the scanning window
        scan_window.destroy()
        
        # Check if threats were found
        if scan_results["threats_found"]:
            if scan_type == "file":
                # For file scan, there's only one file with threats
                self._show_threat_options(path, scan_results["file_threats"][path], scan_results["scan_logs"])
            else:
                # For directory scan, show summary with option to view details
                self._show_directory_scan_summary(path, scan_results["file_threats"], scan_results["scan_logs"])
        else:
            # No threats found
            self._show_safe_notification(path, scan_type, scan_results["scan_logs"])
    
    def _show_threat_options(self, file_path, threats, scan_logs):
        """Show options for dealing with a threat"""
        ThreatOptionsWindow(self.app, file_path, threats, scan_logs)
    
    def _show_directory_scan_summary(self, dir_path, file_threats, scan_logs):
        """Show summary of directory scan with threats"""
        DirectoryScanSummaryWindow(self.app, dir_path, file_threats, scan_logs)
    
    def _show_safe_notification(self, path, scan_type, scan_logs):
        """Show notification for safe scan"""
        SafeScanNotificationWindow(self.app, path, scan_type, scan_logs)
    
    def close_window(self, window):
        """Properly close a window by releasing grab and destroying it"""
        window.grab_release()
        window.destroy()
    
    def open_password_manager(self):
        """Open the password manager application"""
        try:
            password_manager_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_manager", "main.py")
            
            if not os.path.exists(password_manager_path):
                messagebox.showerror("Error", f"Password manager not found at {password_manager_path}")
                return
            
            # Start the password manager in a separate process
            subprocess.Popen(["python3", password_manager_path])
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open password manager: {str(e)}")

class RTMManager:
    """Manages real-time monitoring operations and UI"""
    def __init__(self, app):
        self.app = app
        self.rtm_path = app.rtm_path
        self.detected_files = set()  # Track files with detected threats
        self.file_threats = {}  # Track threats for each file
        self.db_manager = app.db_manager
    
    def show_rtm_config(self):
        """Show RTM configuration window"""
        # Create a pop-up window for RTM configuration
        rtm_window = tk.Toplevel(self.app.root)
        rtm_window.title("Real-Time Monitoring Configuration")
        rtm_window.geometry("800x600")
        rtm_window.configure(bg=COLORS["bg_dark"])
        
        # Make this window appear on top and be modal
        rtm_window.transient(self.app.root)  # Make it appear on top of root
        rtm_window.focus_set()  # Set focus to this window
        rtm_window.grab_set()   # Make it modal
        
        # Add content to the RTM window
        ttk.Label(rtm_window, text="Configure Real-Time Monitoring", 
                style='Title.TLabel').pack(padx=20, pady=20)
        
        # Directory selection frame
        dir_frame = ttk.Frame(rtm_window)
        dir_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(dir_frame, text="Add directories to monitor:", 
                style='Subtitle.TLabel').pack(anchor=tk.W)
        
        # Directory entry and browse button
        entry_frame = ttk.Frame(dir_frame)
        entry_frame.pack(fill=tk.X, pady=10)
        
        self.dir_entry = ttk.Entry(entry_frame, width=60)
        self.dir_entry.pack(side=tk.LEFT, padx=(0, 10), expand=True, fill=tk.X)
        
        # Browse directory function
        def browse_directory():
            rtm_window.grab_release()  # Release grab temporarily
            directory = filedialog.askdirectory(parent=rtm_window)
            rtm_window.grab_set()  # Grab again after dialog closes
            if directory:
                self.dir_entry.delete(0, tk.END)
                self.dir_entry.insert(0, directory)
        
        browse_btn = ttk.Button(entry_frame, text="Browse", style="Secondary.TButton",
                             command=browse_directory)
        browse_btn.pack(side=tk.LEFT)
        
        add_btn = ttk.Button(entry_frame, text="Add", style="Primary.TButton",
                          command=lambda: self.add_directory_to_list(rtm_window))
        add_btn.pack(side=tk.LEFT, padx=10)
        
        # Directory listbox
        list_frame = ttk.Frame(rtm_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.dir_listbox = tk.Listbox(list_frame, bg=COLORS["bg_medium"], fg=COLORS["text"],
                                   font=('Segoe UI', 10), borderwidth=1,
                                   highlightbackground=COLORS["border"], 
                                   selectbackground=COLORS["accent"])
        self.dir_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.dir_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.dir_listbox.config(yscrollcommand=scrollbar.set)
        
        # Buttons for managing the list
        list_btn_frame = ttk.Frame(rtm_window)
        list_btn_frame.pack(fill=tk.X, padx=20, pady=10)
        
        remove_btn = ttk.Button(list_btn_frame, text="Remove Selected", style="Secondary.TButton",
                             command=lambda: self.remove_directory_from_list(rtm_window))
        remove_btn.pack(side=tk.LEFT)
        
        clear_btn = ttk.Button(list_btn_frame, text="Clear All", style="Secondary.TButton",
                            command=lambda: self.dir_listbox.delete(0, tk.END))
        clear_btn.pack(side=tk.LEFT, padx=10)
        
        # RTM control frame
        control_frame = ttk.Frame(rtm_window)
        control_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Status indicator
        status_label = ttk.Label(control_frame, text="Status: ", style='Subtitle.TLabel')
        status_label.pack(side=tk.LEFT)
        
        self.rtm_status_label = ttk.Label(control_frame, text="Inactive", 
                                       foreground=COLORS["error"], background=COLORS["bg_dark"],
                                       font=('Segoe UI', 12, 'bold'))
        self.rtm_status_label.pack(side=tk.LEFT)
        
        # Enable/Disable Button (start/stop RTM)
        self.rtm_button = ttk.Button(control_frame, text="Enable Protection", 
                                   style="Primary.TButton",
                                   command=lambda: self.toggle_rtm(rtm_window))
        self.rtm_button.pack(side=tk.RIGHT)
        
        # Close button to release grab and close window
        close_btn = ttk.Button(control_frame, text="Close", style="Secondary.TButton",
                            command=lambda: self.close_rtm_window(rtm_window))
        close_btn.pack(side=tk.RIGHT, padx=10)
        
        # Show logs toggle
        view_logs_btn = ttk.Button(control_frame, text="View Logs", style="Secondary.TButton",
                                 command=self.app.layout_manager.toggle_rtm_logs_visibility)
        view_logs_btn.pack(side=tk.RIGHT, padx=10)
        
        # If RTM is already running, update the UI
        global process_rtm
        if process_rtm and process_rtm.poll() is None:
            self.rtm_status_label.config(text="Active", foreground=COLORS["success"])
            self.rtm_button.config(text="Disable Protection")
            
            # Also update main window status
            self.app.layout_manager.rtm_status_var.set("Active")
            self.app.layout_manager.rtm_status_indicator.config(fg=COLORS["success"])
    
    def close_rtm_window(self, rtm_window):
        """Properly close RTM window releasing grab"""
        rtm_window.grab_release()
        rtm_window.destroy()
    
    def add_directory_to_list(self, parent_window):
        """Add a directory to the monitoring list"""
        path = self.dir_entry.get().strip()
        if path and os.path.isdir(path):
            # Check if not already in the list
            if path not in self.dir_listbox.get(0, tk.END):
                self.dir_listbox.insert(tk.END, path)
                self.dir_entry.delete(0, tk.END)
            else:
                # Release grab for messagebox
                parent_window.grab_release()
                messagebox.showwarning("Duplicate", "This directory is already in the list.", parent=parent_window)
                parent_window.grab_set()
        else:
            # Release grab for messagebox
            parent_window.grab_release()
            messagebox.showwarning("Invalid Directory", "Please enter a valid directory path.", parent=parent_window)
            parent_window.grab_set()
    
    def remove_directory_from_list(self, parent_window):
        """Remove selected directory from the list"""
        selected = self.dir_listbox.curselection()
        if selected:
            for index in selected[::-1]:
                self.dir_listbox.delete(index)
    
    def toggle_rtm(self, parent_window):
        """Toggle real-time monitoring on/off"""
        global process_rtm
        
        # If RTM is running, stop it
        if process_rtm and process_rtm.poll() is None:
            process_rtm.terminate()
            try:
                process_rtm.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process_rtm.kill()
            
            # Update UI
            self.rtm_status_label.config(text="Inactive", foreground=COLORS["error"])
            self.rtm_button.config(text="Enable Protection")
            self.app.layout_manager.rtm_status_var.set("Inactive")
            self.app.layout_manager.rtm_status_indicator.config(fg=COLORS["error"])
            
            # Log message
            self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                      f"{self.app.get_timestamp()} ⏹️ Real-time monitoring stopped\n", 
                                                      "normal")
            self.app.layout_manager.output_text_rtm.see(tk.END)
            
            return
        
        # Check if we have directories to monitor
        directories = ';'.join(self.dir_listbox.get(0, tk.END))
        if not directories:
            # Release grab for messagebox
            parent_window.grab_release()
            messagebox.showwarning("No Directories", "Please add at least one directory to monitor.", parent=parent_window)
            parent_window.grab_set()
            return
        
        # Start RTM
        try:
            # Clear previous output
            self.app.layout_manager.output_text_rtm.delete(1.0, tk.END)
            
            # Update status
            self.rtm_status_label.config(text="Starting...", foreground=COLORS["warning"])
            self.app.layout_manager.rtm_status_var.set("Starting...")
            self.app.layout_manager.rtm_status_indicator.config(fg=COLORS["warning"])
            
            # Log message
            timestamp = self.app.get_timestamp()
            self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                      f"{timestamp} 🔍 REAL-TIME MONITORING STARTING\n", 
                                                      "header")
            self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                      f"Monitoring directories: {directories}\n\n", 
                                                      "scan_start")
            
            # Start the process
            process_rtm = subprocess.Popen(
                [self.rtm_path, directories], 
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, 
                universal_newlines=True,
                bufsize=1  # Line buffered
            )
            
            # Read output in a separate thread
            threading.Thread(target=self.read_rtm_output, daemon=True).start()
            
            # Update UI
            self.rtm_status_label.config(text="Active", foreground=COLORS["success"])
            self.rtm_button.config(text="Disable Protection")
            self.app.layout_manager.rtm_status_var.set("Active")
            self.app.layout_manager.rtm_status_indicator.config(fg=COLORS["success"])
            
        except Exception as e:
            # Release grab for messagebox
            parent_window.grab_release()
            messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}", parent=parent_window)
            parent_window.grab_set()
            self.app.layout_manager.output_text_rtm.insert(tk.END, f"Error starting RTM: {str(e)}\n", "error")
    
    def read_rtm_output(self):
        """Read and process output from the RTM process"""
        global process_rtm
        
        if not process_rtm:
            return
        
        while process_rtm and process_rtm.poll() is None:
            output_line = process_rtm.stdout.readline()
            if not output_line and process_rtm.poll() is not None:
                break
                
            if output_line:
                # Only process result lines that start with [R]
                if output_line.startswith("[R]"):
                    # Parse result lines
                    result_line = output_line[4:].strip()  # Remove "[R] " prefix
                    parts = result_line.split(":", 3)  # Split by first 3 colons
                    
                    if len(parts) > 0:
                        if parts[0] == "SCAN_START" or parts[0] == "SCAN_COMPLETE":
                            # Don't show these messages for RTM
                            pass
                        elif parts[0] == "DETECTION":
                            detected_path = parts[2]
                            rule_name = parts[1]
                            timestamp = self.app.get_timestamp()
                            
                            # Track threats for this file
                            if detected_path not in self.file_threats:
                                self.file_threats[detected_path] = []
                            self.file_threats[detected_path].append(rule_name)
                            
                            # Add to logs (only visible if user chooses to view logs)
                            def show_detection(p=detected_path, r=rule_name, t=timestamp):
                                self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                                          f"{t} ⚠️ DETECTION: Rule '{r}' matched in {p}\n", 
                                                                          "detection")
                                self.app.layout_manager.output_text_rtm.see(tk.END)
                            
                            self.app.root.after(0, show_detection)
                            
                        elif parts[0] == "UNSAFE" and len(parts) >= 4:
                            unsafe_path = parts[1]
                            threat_count = parts[2]
                            threats = parts[3]
                            timestamp = self.app.get_timestamp()
                            
                            # Only show alert if this is the first time seeing this file
                            if unsafe_path not in self.detected_files:
                                self.detected_files.add(unsafe_path)
                                
                                # Show threat options popup directly for RTM threats
                                # We don't show the scanning screen for RTM threats
                                threat_list = threats.split(", ")
                                
                                def show_rtm_alert(path=unsafe_path, threat_list=threat_list):
                                    # Don't show scanning status screen, directly show options popup
                                    self.app.root.after_idle(
                                        lambda p=path, tl=threat_list: 
                                        ThreatOptionsWindow(self.app, p, tl, is_rtm=True)
                                    )
                                
                                # Schedule alert to show after logging
                                self.app.root.after(100, show_rtm_alert)
                            
                            # Update threats for this file
                            self.file_threats[unsafe_path] = threats.split(", ")
                            
                            # Add to logs (only visible if user chooses to view logs)
                            def show_unsafe(p=unsafe_path, c=threat_count, t_rules=threats, t=timestamp):
                                self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                                          f"{t} ❌ UNSAFE: Found {c} threat(s) in {p}\n", 
                                                                          "unsafe")
                                self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                                          f"   Matched rules: {t_rules}\n", 
                                                                          "unsafe_details")
                                self.app.layout_manager.output_text_rtm.see(tk.END)
                            
                            self.app.root.after(0, show_unsafe)
                            
                        elif parts[0] == "FILE_MODIFIED":
                            timestamp = self.app.get_timestamp()
                            modified_path = parts[1]
                            
                            # Only log this event if it's not an excepted file
                            if not self.db_manager.is_file_excepted(modified_path):
                                def show_modified(p=modified_path, t=timestamp):
                                    self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                                              f"{t} 🔄 FILE MODIFIED: {p}\n", 
                                                                              "change")
                                    self.app.layout_manager.output_text_rtm.see(tk.END)
                                
                                self.app.root.after(0, show_modified)
                            
                        elif parts[0] == "FILE_CREATED":
                            timestamp = self.app.get_timestamp()
                            created_path = parts[1]
                            
                            # Only log this event if it's not an excepted file
                            if not self.db_manager.is_file_excepted(created_path):
                                def show_created(p=created_path, t=timestamp):
                                    self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                                              f"{t} ➕ FILE CREATED: {p}\n", 
                                                                              "created")
                                    self.app.layout_manager.output_text_rtm.see(tk.END)
                                
                                self.app.root.after(0, show_created)
                            
                        elif parts[0] == "FILE_DELETED":
                            timestamp = self.app.get_timestamp()
                            deleted_path = parts[1]
                            
                            # Only log this event if it's not an excepted file
                            if not self.db_manager.is_file_excepted(deleted_path):
                                def show_deleted(p=deleted_path, t=timestamp):
                                    self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                                              f"{t} ➖ FILE DELETED: {p}\n", 
                                                                              "deleted")
                                    self.app.layout_manager.output_text_rtm.see(tk.END)
                                
                                self.app.root.after(0, show_deleted)
                            
                        elif parts[0] == "MONITORING_ACTIVE":
                            timestamp = self.app.get_timestamp()
                            monitored_path = parts[1]
                            
                            def show_monitoring(p=monitored_path, t=timestamp):
                                self.app.layout_manager.output_text_rtm.insert(tk.END, 
                                                                          f"{t} 🔍 MONITORING ACTIVE: {p}\n", 
                                                                          "monitoring")
                                self.app.layout_manager.output_text_rtm.see(tk.END)
                            
                            self.app.root.after(0, show_monitoring)
    
    def show_exceptions_manager(self):
        """Show the exceptions manager window"""
        ExceptionsManagerWindow(self.app)

class ThreatOptionsWindow:
    """Window for showing threat options to the user"""
    def __init__(self, app, file_path, threats, scan_logs=None, is_rtm=False):
        self.app = app
        self.file_path = file_path
        self.threats = threats
        self.scan_logs = scan_logs or []
        self.is_rtm = is_rtm
        
        # Create window
        self.window = tk.Toplevel(app.root)
        self.window.title("⚠️ Threat Detected!")
        self.window.geometry("500x340")
        self.window.configure(bg=COLORS["bg_dark"])
        
        # Give it focus and make it modal
        self.window.transient(app.root)
        self.window.focus_set()
        self.window.grab_set()
        
        # Add some warning styling
        self.window.attributes('-topmost', True)
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the UI elements"""
        # Warning icon and header
        header_frame = ttk.Frame(self.window)
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Try to load warning icon
        try:
            img = Image.open("antivirus/images/warning.png")
            img = img.resize((48, 48), Image.LANCZOS)
            warning_icon = ImageTk.PhotoImage(img)
            icon_label = ttk.Label(header_frame, image=warning_icon, background=COLORS["bg_dark"])
            icon_label.image = warning_icon  # Keep a reference
            icon_label.pack(side=tk.LEFT, padx=(0, 10))
        except Exception:
            # No icon fallback - use text instead
            pass
        
        # Header text
        ttk.Label(header_frame, text="Security Threat Detected!", 
                style='Title.TLabel', foreground=COLORS["error"]).pack(side=tk.LEFT)
        
        # Content area
        content_frame = ttk.Frame(self.window)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # File information
        ttk.Label(content_frame, 
                text=f"The following file has been identified as potentially harmful:",
                style='Subtitle.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        # File path (with filename in bold)
        file_name = os.path.basename(self.file_path)
        file_dir = os.path.dirname(self.file_path)
        
        file_frame = ttk.Frame(content_frame)
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(file_frame, text="File:", 
                style='Info.TLabel', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        
        ttk.Label(file_frame, text=f"{file_name}", 
                foreground=COLORS["error"],
                font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        path_frame = ttk.Frame(content_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(path_frame, text="Location:", 
                style='Info.TLabel', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        
        ttk.Label(path_frame, text=f"{file_dir}", 
                style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        
        # Threat count
        threat_count = len(self.threats) if isinstance(self.threats, list) else 1
        ttk.Label(content_frame, 
                text=f"Found {threat_count} security {'threat' if threat_count == 1 else 'threats'}.",
                style='Subtitle.TLabel', 
                foreground=COLORS["warning"]).pack(anchor=tk.W, pady=10)
        
        # Source information
        source_frame = ttk.Frame(content_frame)
        source_frame.pack(fill=tk.X, pady=5)
        ttk.Label(source_frame, text="Detection source:", 
                style='Info.TLabel', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        ttk.Label(source_frame, text=f"{'Real-Time Monitoring' if self.is_rtm else 'Manual Scan'}", 
                style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        
        # Buttons frame
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Action buttons
        delete_btn = ttk.Button(button_frame, text="Delete File", style="Primary.TButton",
                            command=self.delete_file)
        delete_btn.pack(side=tk.LEFT)
        
        # Details button
        details_btn = ttk.Button(button_frame, text="More Details", style="Secondary.TButton",
                            command=self.show_details)
        details_btn.pack(side=tk.LEFT, padx=10)
        
        # Exception button (changed from "Ignore")
        except_btn = ttk.Button(button_frame, text="Add as Exception", style="Secondary.TButton",
                            command=self.add_exception)
        except_btn.pack(side=tk.RIGHT)
    
# Update these methods in the ThreatOptionsWindow class

    def delete_file(self):
        """Delete the infected file"""
        try:
            # Delete the file
            os.remove(self.file_path)
            
            # Record this action in threat history
            threat_types = ", ".join(self.threats) if isinstance(self.threats, list) else self.threats
            self.app.db_manager.add_threat_history(self.file_path, threat_types, "Deleted")
            
            # Update alert to show success
            for widget in self.window.winfo_children():
                widget.destroy()
            
            success_frame = ttk.Frame(self.window)
            success_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            ttk.Label(success_frame, text="✅ File successfully deleted!", 
                    foreground=COLORS["success"],
                    font=('Segoe UI', 12, 'bold')).pack(anchor=tk.CENTER, pady=20)
            
            # Add close button
            ttk.Button(success_frame, text="Close", style="Secondary.TButton",
                    command=self.window.destroy).pack(pady=10)
            
        except Exception as e:
            # Show error if deletion fails
            messagebox.showerror("Deletion Error", f"Could not delete file: {str(e)}", parent=self.window)

    def add_exception(self):
        """Add file to exceptions database"""
        # Create dialog for adding reason
        reason_dialog = tk.Toplevel(self.window)
        reason_dialog.title("Add Exception")
        reason_dialog.geometry("400x200")
        reason_dialog.configure(bg=COLORS["bg_dark"])
        reason_dialog.transient(self.window)
        reason_dialog.grab_set()
        
        ttk.Label(reason_dialog, text="Add file to exceptions list", 
                style='Subtitle.TLabel').pack(padx=20, pady=10)
        
        ttk.Label(reason_dialog, text="Optional reason for exception:", 
                style='Info.TLabel').pack(anchor=tk.W, padx=20, pady=5)
        
        reason_entry = ttk.Entry(reason_dialog, width=40)
        reason_entry.pack(fill=tk.X, padx=20, pady=5)
        
        btn_frame = ttk.Frame(reason_dialog)
        btn_frame.pack(fill=tk.X, padx=20, pady=20)
        
        def confirm_exception():
            # Add to database and close dialogs
            result = self.app.db_manager.add_exception(self.file_path, reason_entry.get())
            if result:
                # Record this action in threat history
                threat_types = ", ".join(self.threats) if isinstance(self.threats, list) else self.threats
                self.app.db_manager.add_threat_history(
                    self.file_path, 
                    threat_types, 
                    f"Added to exceptions: {reason_entry.get() if reason_entry.get() else 'No reason provided'}"
                )
                
                messagebox.showinfo("Success", "File added to exceptions list.", parent=reason_dialog)
                reason_dialog.destroy()
                self.window.destroy()
            else:
                messagebox.showerror("Error", "Failed to add exception. Please try again.", parent=reason_dialog)
        
        ttk.Button(btn_frame, text="Add Exception", style="Primary.TButton",
                command=confirm_exception).pack(side=tk.LEFT)
        
        ttk.Button(btn_frame, text="Cancel", style="Secondary.TButton",
                command=reason_dialog.destroy).pack(side=tk.RIGHT)

    
    def show_details(self):
        """Show detailed threat information and logs"""
        details_window = tk.Toplevel(self.window)
        details_window.title("Threat Details")
        details_window.geometry("750x500")
        details_window.configure(bg=COLORS["bg_dark"])
        details_window.transient(self.window)
        
        # Details header
        ttk.Label(details_window, text="Detailed Threat Information", 
                style='Title.TLabel').pack(padx=20, pady=10)
        
        # File path information
        path_frame = ttk.Frame(details_window)
        path_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(path_frame, text="File:", 
                style='Info.TLabel', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        ttk.Label(path_frame, text=self.file_path, 
                style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        
        # Create notebook for tabbed interface
        notebook = ttk.Notebook(details_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Tab 1: Detected rules
        rules_frame = ttk.Frame(notebook)
        notebook.add(rules_frame, text="Detected Threats")
        
        # Use Treeview to show rules in a nice table
        columns = ('rule_id', 'description', 'severity')
        rules_treeview = ttk.Treeview(rules_frame, columns=columns, show='headings')
        
        # Define headings
        rules_treeview.heading('rule_id', text='Rule ID')
        rules_treeview.heading('description', text='Description')
        rules_treeview.heading('severity', text='Severity')
        
        # Define column widths
        rules_treeview.column('rule_id', width=120)
        rules_treeview.column('description', width=400)
        rules_treeview.column('severity', width=100)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(rules_frame, orient=tk.VERTICAL, command=rules_treeview.yview)
        rules_treeview.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        rules_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Insert rule data
        if isinstance(self.threats, list):
            for i, rule in enumerate(self.threats):
                rules_treeview.insert('', tk.END, values=(rule, f"Detected threat pattern: {rule}", "High"))
        else:
            # Handle case where threats is a string
            rules_treeview.insert('', tk.END, values=(self.threats, f"Detected threat pattern: {self.threats}", "High"))
        
        # Tab 2: Scan Logs
        if self.scan_logs:
            logs_frame = ttk.Frame(notebook)
            notebook.add(logs_frame, text="Scan Logs")
            
            logs_text = tk.Text(logs_frame, wrap='word',
                              font=('Segoe UI', 10),
                              bg=COLORS["bg_medium"],
                              fg=COLORS["text"],
                              border=0)
            logs_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            logs_scrollbar = ttk.Scrollbar(logs_frame, orient="vertical", command=logs_text.yview)
            logs_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            logs_text.config(yscrollcommand=logs_scrollbar.set)
            
            # Insert log data
            for log_entry in self.scan_logs:
                logs_text.insert(tk.END, f"{log_entry}\n")
        
        # Bottom buttons
        btn_frame = ttk.Frame(details_window)
        btn_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Button(btn_frame, text="Close", style="Secondary.TButton",
                command=details_window.destroy).pack(side=tk.RIGHT)


class DirectoryScanSummaryWindow:
    """Window for showing directory scan summary with threats"""
    def __init__(self, app, dir_path, file_threats, scan_logs=None):
        self.app = app
        self.dir_path = dir_path
        self.file_threats = file_threats
        self.scan_logs = scan_logs or []
        
        # Create window
        self.window = tk.Toplevel(app.root)
        self.window.title(f"Directory Scan - Threats Found! ({len(file_threats)})")
        self.window.geometry("750x500")
        self.window.configure(bg=COLORS["bg_dark"])
        
        # Give it focus and make it modal
        self.window.transient(app.root)
        self.window.focus_set()
        self.window.grab_set()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the UI elements"""
        # Header with summary
        header_frame = ttk.Frame(self.window)
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Try to load warning icon
        try:
            img = Image.open("antivirus/images/warning.png")
            img = img.resize((32, 32), Image.LANCZOS)
            warning_icon = ImageTk.PhotoImage(img)
            icon_label = ttk.Label(header_frame, image=warning_icon, background=COLORS["bg_dark"])
            icon_label.image = warning_icon  # Keep a reference
            icon_label.pack(side=tk.LEFT, padx=(0, 10))
        except Exception:
            # No icon fallback
            pass
        
        ttk.Label(header_frame, text=f"Threats Found in Directory: {len(self.file_threats)} files", 
                style='Title.TLabel', foreground=COLORS["error"]).pack(side=tk.LEFT)
        
        # Path display
        path_frame = ttk.Frame(self.window)
        path_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(path_frame, text="Directory:", 
                style='Info.TLabel', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        ttk.Label(path_frame, text=self.dir_path, 
                style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        
        # Create notebook for tabbed interface
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Tab 1: Detected threats summary
        threats_frame = ttk.Frame(notebook)
        notebook.add(threats_frame, text="Threats Found")
        
        # Use Treeview to show threat files
        columns = ('file', 'threats', 'count')
        threats_treeview = ttk.Treeview(threats_frame, columns=columns, show='headings')
        
        # Define headings
        threats_treeview.heading('file', text='File')
        threats_treeview.heading('threats', text='Detected Threats')
        threats_treeview.heading('count', text='Count')
        
        # Define column widths
        threats_treeview.column('file', width=300)
        threats_treeview.column('threats', width=300)
        threats_treeview.column('count', width=50, anchor='center')
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=threats_treeview.yview)
        threats_treeview.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        threats_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Insert threat data
        for filepath, threats in self.file_threats.items():
            threats_treeview.insert('', tk.END, values=(
                filepath,
                ", ".join(threats),
                len(threats)
            ))
        
        # Bind double click to show details for specific file
        threats_treeview.bind("<Double-1>", self.on_file_double_click)
        
        # Tab 2: Scan Logs
        if self.scan_logs:
            logs_frame = ttk.Frame(notebook)
            notebook.add(logs_frame, text="Full Scan Log")
            
            logs_text = tk.Text(logs_frame, wrap='word',
                              font=('Segoe UI', 10),
                              bg=COLORS["bg_medium"],
                              fg=COLORS["text"],
                              border=0)
            logs_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            logs_scrollbar = ttk.Scrollbar(logs_frame, orient="vertical", command=logs_text.yview)
            logs_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            logs_text.config(yscrollcommand=logs_scrollbar.set)
            
            # Insert log data
            for log_entry in self.scan_logs:
                logs_text.insert(tk.END, f"{log_entry}\n")
        
        # Button frame
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Button(button_frame, text="View Selected File", style="Primary.TButton",
                command=self.view_selected_file).pack(side=tk.LEFT)
        
        ttk.Button(button_frame, text="Add All as Exceptions", style="Secondary.TButton",
                command=self.add_all_exceptions).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(button_frame, text="Close", style="Secondary.TButton",
                command=self.window.destroy).pack(side=tk.RIGHT)
        
        # Store the treeview for later access
        self.threats_treeview = threats_treeview
    
    def on_file_double_click(self, event):
        """Handle double-click on a file in the threats list"""
        self.view_selected_file()
    
    def view_selected_file(self):
        """Show details for the selected file"""
        selected_items = self.threats_treeview.selection()
        
        if not selected_items:
            messagebox.showinfo("No Selection", "Please select a file to view.", parent=self.window)
            return
        
        # Get the first selected item
        item = selected_items[0]
        file_path = self.threats_treeview.item(item, "values")[0]
        
        # Get threats for this file
        threats = self.file_threats.get(file_path, [])
        
        # Show the threat options window for this file
        self.window.grab_release()  # Release grab so the new window can take it
        ThreatOptionsWindow(self.app, file_path, threats, self.scan_logs)
        self.window.grab_set()  # Re-grab when returning
    
    def add_all_exceptions(self):
        """Add all infected files to exceptions"""
        # Confirm with user
        if not messagebox.askyesno(
            "Confirm Action", 
            f"Are you sure you want to add all {len(self.file_threats)} files to exceptions?",
            parent=self.window
        ):
            return
            
        # Add each file to exceptions
        success_count = 0
        for file_path in self.file_threats.keys():
            if self.app.db_manager.add_exception(file_path, "Added from directory scan"):
                success_count += 1
        
        # Show result
        if success_count == len(self.file_threats):
            messagebox.showinfo(
                "Success", 
                f"All {success_count} files have been added to exceptions.", 
                parent=self.window
            )
            self.window.destroy()
        else:
            messagebox.showwarning(
                "Partial Success", 
                f"Added {success_count} of {len(self.file_threats)} files to exceptions.", 
                parent=self.window
            )


class SafeScanNotificationWindow:
    """Window for showing notification when no threats are found"""
    def __init__(self, app, path, scan_type, scan_logs=None):
        self.app = app
        self.path = path
        self.scan_type = scan_type  # "file" or "directory"
        self.scan_logs = scan_logs or []
        
        # Create window
        self.window = tk.Toplevel(app.root)
        self.window.title("Scan Complete - No Threats Found")
        self.window.geometry("500x300")
        self.window.configure(bg=COLORS["bg_dark"])
        
        # Give it focus and make it modal
        self.window.transient(app.root)
        self.window.focus_set()
        self.window.grab_set()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the UI elements"""
        # Header with success message
        header_frame = ttk.Frame(self.window)
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Try to load success icon
        try:
            img = Image.open("antivirus/images/shield.png")
            img = img.resize((48, 48), Image.LANCZOS)
            success_icon = ImageTk.PhotoImage(img)
            icon_label = ttk.Label(header_frame, image=success_icon, background=COLORS["bg_dark"])
            icon_label.image = success_icon  # Keep a reference
            icon_label.pack(side=tk.LEFT, padx=(0, 10))
        except Exception:
            # No icon fallback
            pass
        
        ttk.Label(header_frame, text="Scan Complete - Safe!", 
                style='Title.TLabel', foreground=COLORS["success"]).pack(side=tk.LEFT)
        
        # Content area
        content_frame = ttk.Frame(self.window)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Success message
        if self.scan_type == "file":
            message = f"No threats were detected in the file:\n{self.path}"
        else:
            message = f"No threats were detected in any files in:\n{self.path}"
        
        ttk.Label(content_frame, text=message,
                style='Subtitle.TLabel').pack(anchor=tk.CENTER, pady=20)
        
        # View logs button if we have logs
        if self.scan_logs:
            show_logs_btn = ttk.Button(content_frame, text="View Scan Log", 
                                    style="Secondary.TButton",
                                    command=self.show_logs)
            show_logs_btn.pack(pady=10)
        
        # Button frame
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Button(button_frame, text="Close", style="Primary.TButton",
                command=self.window.destroy).pack(side=tk.RIGHT)
    
    def show_logs(self):
        """Show the full scan logs"""
        logs_window = tk.Toplevel(self.window)
        logs_window.title("Scan Logs")
        logs_window.geometry("600x400")
        logs_window.configure(bg=COLORS["bg_dark"])
        logs_window.transient(self.window)
        
        # Header
        ttk.Label(logs_window, text="Complete Scan Log", 
                style='Title.TLabel').pack(padx=20, pady=10)
        
        # Log display
        log_frame = ttk.Frame(logs_window)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Text widget with scrollbar
        logs_text = tk.Text(log_frame, wrap='word',
                          font=('Segoe UI', 10),
                          bg=COLORS["bg_medium"],
                          fg=COLORS["text"],
                          border=0)
        logs_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=logs_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        logs_text.config(yscrollcommand=scrollbar.set)
        
        # Insert log data
        for log_entry in self.scan_logs:
            logs_text.insert(tk.END, f"{log_entry}\n")
        
        # Close button
        ttk.Button(logs_window, text="Close", style="Secondary.TButton",
                command=logs_window.destroy).pack(pady=10)
        

class ExceptionsManagerWindow:
    """Window for managing file and directory exceptions"""
    def __init__(self, app):
        self.app = app
        self.db_manager = app.db_manager
        
        # Create window
        self.window = tk.Toplevel(app.root)
        self.window.title("Exceptions Manager")
        self.window.geometry("800x500")
        self.window.configure(bg=COLORS["bg_dark"])
        
        # Give it focus and make it modal
        self.window.transient(app.root)
        self.window.focus_set()
        self.window.grab_set()
        
        self.setup_ui()
        self.load_exceptions()
    
    def setup_ui(self):
        """Set up the UI elements"""
        # Header
        header_frame = ttk.Frame(self.window)
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(header_frame, text="Manage Scan & Monitoring Exceptions", 
                style='Title.TLabel').pack(side=tk.LEFT)
        
        # Description
        ttk.Label(self.window, text="Files and directories listed here will be ignored during scanning and monitoring.", 
                style='Info.TLabel').pack(anchor=tk.W, padx=20, pady=5)
        
        # Exceptions list
        list_frame = ttk.Frame(self.window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Use Treeview to show exceptions
        columns = ('path', 'reason', 'date')
        self.exceptions_treeview = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        # Define headings
        self.exceptions_treeview.heading('path', text='File/Directory Path')
        self.exceptions_treeview.heading('reason', text='Reason')
        self.exceptions_treeview.heading('date', text='Date Added')
        
        # Define column widths
        self.exceptions_treeview.column('path', width=400)
        self.exceptions_treeview.column('reason', width=200)
        self.exceptions_treeview.column('date', width=150)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.exceptions_treeview.yview)
        self.exceptions_treeview.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.exceptions_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Button frame
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Button(button_frame, text="Add New Exception", style="Primary.TButton",
                command=self.add_new_exception).pack(side=tk.LEFT)
        
        ttk.Button(button_frame, text="Remove Selected", style="Secondary.TButton",
                command=self.remove_selected).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(button_frame, text="Close", style="Secondary.TButton",
                command=self.window.destroy).pack(side=tk.RIGHT)
    
    def load_exceptions(self):
        """Load exceptions from database"""
        # Clear existing items
        for item in self.exceptions_treeview.get_children():
            self.exceptions_treeview.delete(item)
        
        # Get exceptions from database
        exceptions = self.db_manager.get_all_exceptions()
        
        # Add to treeview
        for path, reason, date in exceptions:
            self.exceptions_treeview.insert('', tk.END, values=(path, reason or '', date))
    
    def add_new_exception(self):
        """Add a new file or directory to exceptions"""
        # Create dialog for selecting file or directory
        add_dialog = tk.Toplevel(self.window)
        add_dialog.title("Add Exception")
        add_dialog.geometry("500x220")
        add_dialog.configure(bg=COLORS["bg_dark"])
        add_dialog.transient(self.window)
        add_dialog.grab_set()
        
        ttk.Label(add_dialog, text="Add new file or directory to exceptions", 
                style='Subtitle.TLabel').pack(padx=20, pady=10)
        
        # Path frame
        path_frame = ttk.Frame(add_dialog)
        path_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(path_frame, text="Path:", 
                style='Info.TLabel').pack(side=tk.LEFT)
        
        path_entry = ttk.Entry(path_frame, width=50)
        path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Browse buttons
        browse_frame = ttk.Frame(add_dialog)
        browse_frame.pack(fill=tk.X, padx=20, pady=5)
        
        def browse_file():
            add_dialog.grab_release()
            file_path = filedialog.askopenfilename(parent=add_dialog)
            add_dialog.grab_set()
            if file_path:
                path_entry.delete(0, tk.END)
                path_entry.insert(0, file_path)
        
        def browse_dir():
            add_dialog.grab_release()
            dir_path = filedialog.askdirectory(parent=add_dialog)
            add_dialog.grab_set()
            if dir_path:
                path_entry.delete(0, tk.END)
                path_entry.insert(0, dir_path)
        
        ttk.Button(browse_frame, text="Browse File", style="Secondary.TButton",
                command=browse_file).pack(side=tk.LEFT)
        
        ttk.Button(browse_frame, text="Browse Directory", style="Secondary.TButton",
                command=browse_dir).pack(side=tk.LEFT, padx=10)
        
        # Reason entry
        reason_frame = ttk.Frame(add_dialog)
        reason_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(reason_frame, text="Reason (optional):", 
                style='Info.TLabel').pack(anchor=tk.W)
        
        reason_entry = ttk.Entry(reason_frame, width=50)
        reason_entry.pack(fill=tk.X, pady=5)
        
        # Button frame
        btn_frame = ttk.Frame(add_dialog)
        btn_frame.pack(fill=tk.X, padx=20, pady=20)
        
        def add_exception():
            path = path_entry.get().strip()
            reason = reason_entry.get().strip()
            
            if not path:
                messagebox.showwarning("Error", "Please enter a file or directory path.", parent=add_dialog)
                return
            
            if not os.path.exists(path):
                if not messagebox.askyesno(
                    "Path Not Found", 
                    f"The specified path does not exist:\n{path}\n\nAdd it anyway?", 
                    parent=add_dialog
                ):
                    return
            
            # Add to database
            result = self.db_manager.add_exception(path, reason)
            
            if result:
                messagebox.showinfo("Success", "Exception added successfully.", parent=add_dialog)
                add_dialog.destroy()
                # Refresh the list
                self.load_exceptions()
            else:
                messagebox.showerror("Error", "Failed to add exception. Please try again.", parent=add_dialog)
        
        ttk.Button(btn_frame, text="Add", style="Primary.TButton",
                command=add_exception).pack(side=tk.LEFT)
        
        ttk.Button(btn_frame, text="Cancel", style="Secondary.TButton",
                command=add_dialog.destroy).pack(side=tk.RIGHT)
    
    def remove_selected(self):
        """Remove selected exceptions"""
        selected_items = self.exceptions_treeview.selection()
        
        if not selected_items:
            messagebox.showinfo("No Selection", "Please select items to remove.", parent=self.window)
            return
        
        # Confirm removal
        if not messagebox.askyesno(
            "Confirm Removal", 
            f"Are you sure you want to remove {len(selected_items)} exception(s)?", 
            parent=self.window
        ):
            return
        
        # Remove each selected item
        success_count = 0
        for item in selected_items:
            path = self.exceptions_treeview.item(item, "values")[0]
            if self.db_manager.remove_exception(path):
                success_count += 1
        
        # Show result
        if success_count == len(selected_items):
            messagebox.showinfo(
                "Success", 
                f"Successfully removed {success_count} exception(s).", 
                parent=self.window
            )
        else:
            messagebox.showwarning(
                "Partial Success", 
                f"Removed {success_count} of {len(selected_items)} exception(s).", 
                parent=self.window
            )
        
        # Refresh the list
        self.load_exceptions()

class HistoryManagerWindow:
    """Window for viewing scan history and threat detections"""
    def __init__(self, app):
        self.app = app
        self.db_manager = app.db_manager
        
        # Create window
        self.window = tk.Toplevel(app.root)
        self.window.title("Scan History")
        self.window.geometry("900x600")
        self.window.configure(bg=COLORS["bg_dark"])
        
        # Give it focus and make it modal
        self.window.transient(app.root)
        self.window.focus_set()
        self.window.grab_set()
        
        self.setup_ui()
        self.load_history()
    
    def setup_ui(self):
        """Set up the UI elements"""
        # Header
        header_frame = ttk.Frame(self.window)
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(header_frame, text="Scan and Threat History", 
                style='Title.TLabel').pack(side=tk.LEFT)
        
        # Description
        ttk.Label(self.window, text="Review past scans and detected threats", 
                style='Info.TLabel').pack(anchor=tk.W, padx=20, pady=5)
        
        # Notebook for tabbed interface
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Tab 1: Scan History
        self.scan_history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_history_tab, text="Scan History")
        
        # Tab 2: Threat History
        self.threat_history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.threat_history_tab, text="Detected Threats")
        
        # Set up scan history tab
        self.setup_scan_history_tab()
        
        # Set up threat history tab
        self.setup_threat_history_tab()
        
        # Button frame
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Button(button_frame, text="Clear History", style="Secondary.TButton",
                command=self.confirm_clear_history).pack(side=tk.LEFT)
        
        ttk.Button(button_frame, text="Export CSV", style="Secondary.TButton",
                command=self.export_to_csv).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(button_frame, text="Close", style="Secondary.TButton",
                command=self.window.destroy).pack(side=tk.RIGHT)
    
    def setup_scan_history_tab(self):
        """Set up the scan history tab with treeview"""
        # Use Treeview to show scan history
        columns = ('date', 'type', 'path', 'threats')
        self.scan_history_treeview = ttk.Treeview(self.scan_history_tab, columns=columns, show='headings')
        
        # Define headings
        self.scan_history_treeview.heading('date', text='Date & Time')
        self.scan_history_treeview.heading('type', text='Scan Type')
        self.scan_history_treeview.heading('path', text='Path')
        self.scan_history_treeview.heading('threats', text='Threats Found')
        
        # Define column widths
        self.scan_history_treeview.column('date', width=150)
        self.scan_history_treeview.column('type', width=100)
        self.scan_history_treeview.column('path', width=450)
        self.scan_history_treeview.column('threats', width=100, anchor='center')
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(self.scan_history_tab, orient=tk.VERTICAL, command=self.scan_history_treeview.yview)
        self.scan_history_treeview.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.scan_history_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add filtering controls
        filter_frame = ttk.Frame(self.scan_history_tab)
        filter_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(filter_frame, text="Filter by:", style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        
        # Filter by scan type
        self.scan_type_var = tk.StringVar(value="All")
        scan_type_combo = ttk.Combobox(filter_frame, textvariable=self.scan_type_var, 
                                     state="readonly", width=15)
        scan_type_combo['values'] = ('All', 'file', 'directory')
        scan_type_combo.pack(side=tk.LEFT, padx=5)
        scan_type_combo.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        
        # Filter by date range
        ttk.Label(filter_frame, text="From:", style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        self.from_date_entry = ttk.Entry(filter_frame, width=12)
        self.from_date_entry.pack(side=tk.LEFT, padx=2)
        self.from_date_entry.insert(0, "YYYY-MM-DD")
        
        ttk.Label(filter_frame, text="To:", style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        self.to_date_entry = ttk.Entry(filter_frame, width=12)
        self.to_date_entry.pack(side=tk.LEFT, padx=2)
        self.to_date_entry.insert(0, "YYYY-MM-DD")
        
        # Apply filter button
        ttk.Button(filter_frame, text="Apply Filter", style="Secondary.TButton",
                command=self.apply_filters).pack(side=tk.LEFT, padx=10)
        
        # Reset filter button
        ttk.Button(filter_frame, text="Reset", style="Secondary.TButton",
                command=self.reset_filters).pack(side=tk.LEFT, padx=5)
    
    def setup_threat_history_tab(self):
        """Set up the threat history tab with treeview"""
        # Use Treeview to show threat history
        columns = ('date', 'file', 'threat_type', 'action')
        self.threat_history_treeview = ttk.Treeview(self.threat_history_tab, columns=columns, show='headings')
        
        # Define headings
        self.threat_history_treeview.heading('date', text='Date & Time')
        self.threat_history_treeview.heading('file', text='File')
        self.threat_history_treeview.heading('threat_type', text='Threat Type')
        self.threat_history_treeview.heading('action', text='Action Taken')
        
        # Define column widths
        self.threat_history_treeview.column('date', width=150)
        self.threat_history_treeview.column('file', width=350)
        self.threat_history_treeview.column('threat_type', width=150)
        self.threat_history_treeview.column('action', width=150)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(self.threat_history_tab, orient=tk.VERTICAL, command=self.threat_history_treeview.yview)
        self.threat_history_treeview.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.threat_history_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    def load_history(self):
        """Load history data from database"""
        # Clear existing items
        for item in self.scan_history_treeview.get_children():
            self.scan_history_treeview.delete(item)
        
        for item in self.threat_history_treeview.get_children():
            self.threat_history_treeview.delete(item)
        
        # Get scan history from database
        scan_history = self.db_manager.get_scan_history(100)  # Get the last 100 scans
        
        # Add to scan history treeview
        for scan_type, path, threats_found, date_scanned in scan_history:
            self.scan_history_treeview.insert('', tk.END, values=(
                date_scanned, 
                scan_type, 
                path,
                threats_found
            ))
        
        # Get threat history from database
        threat_history = self.db_manager.get_threat_history(100)  # Get the last 100 threats
        
        # Add to threat history treeview
        for date_detected, file_path, threat_type, action_taken in threat_history:
            self.threat_history_treeview.insert('', tk.END, values=(
                date_detected,
                file_path,
                threat_type,
                action_taken
            ))
    
    def apply_filters(self):
        """Apply filters to scan history"""
        # Get filter values
        scan_type_filter = self.scan_type_var.get()
        from_date = self.from_date_entry.get().strip()
        to_date = self.to_date_entry.get().strip()
        
        # Validate date format
        if from_date != "YYYY-MM-DD" and not self._validate_date_format(from_date):
            messagebox.showwarning("Invalid Date Format", "From date should be in YYYY-MM-DD format.", parent=self.window)
            return
        
        if to_date != "YYYY-MM-DD" and not self._validate_date_format(to_date):
            messagebox.showwarning("Invalid Date Format", "To date should be in YYYY-MM-DD format.", parent=self.window)
            return
        
        # Convert 'All' to None for SQL query
        if scan_type_filter == "All":
            scan_type_filter = None
        
        # Convert placeholder text to None
        if from_date == "YYYY-MM-DD":
            from_date = None
        
        if to_date == "YYYY-MM-DD":
            to_date = None
        
        # Get filtered history from database
        scan_history = self.db_manager.get_filtered_scan_history(
            scan_type=scan_type_filter,
            start_date=from_date,
            end_date=to_date,
            limit=100
        )
        
        # Clear existing items
        for item in self.scan_history_treeview.get_children():
            self.scan_history_treeview.delete(item)
        
        # Add filtered items
        for scan_type, path, threats_found, date_scanned in scan_history:
            self.scan_history_treeview.insert('', tk.END, values=(
                date_scanned, 
                scan_type, 
                path,
                threats_found
            ))
    
    def reset_filters(self):
        """Reset filters to default values"""
        self.scan_type_var.set("All")
        self.from_date_entry.delete(0, tk.END)
        self.from_date_entry.insert(0, "YYYY-MM-DD")
        self.to_date_entry.delete(0, tk.END)
        self.to_date_entry.insert(0, "YYYY-MM-DD")
        
        # Reload all history
        self.load_history()
    
    def _validate_date_format(self, date_str):
        """Validate date string format (YYYY-MM-DD)"""
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
            return True
        except ValueError:
            return False
    
    def confirm_clear_history(self):
        """Confirm before clearing history"""
        if messagebox.askyesno(
            "Confirm Clear History", 
            "Are you sure you want to clear all scan and threat history?\nThis action cannot be undone.",
            parent=self.window
        ):
            self.clear_history()
    
    def clear_history(self):
        """Clear scan and threat history from the database"""
        # Clear scan history
        self.db_manager.clear_scan_history()
        
        # Clear threat history
        self.db_manager.clear_threat_history()
        
        # Reload the treeviews (should be empty now)
        self.load_history()
        
        messagebox.showinfo(
            "History Cleared", 
            "Scan and threat history has been successfully cleared.",
            parent=self.window
        )
    
    def export_to_csv(self):
        """Export history data to CSV file"""
        tab_index = self.notebook.index(self.notebook.select())
        
        if tab_index == 0:  # Scan History tab
            filename = filedialog.asksaveasfilename(
                parent=self.window,
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Export Scan History"
            )
            
            if not filename:
                return
            
            try:
                with open(filename, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    # Write header
                    writer.writerow(['Date & Time', 'Scan Type', 'Path', 'Threats Found'])
                    
                    # Write data rows
                    for item_id in self.scan_history_treeview.get_children():
                        values = self.scan_history_treeview.item(item_id, 'values')
                        writer.writerow(values)
                
                messagebox.showinfo("Export Successful", f"Scan history exported to {filename}", parent=self.window)
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {str(e)}", parent=self.window)
                
        else:  # Threat History tab
            filename = filedialog.asksaveasfilename(
                parent=self.window,
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Export Threat History"
            )
            
            if not filename:
                return
            
            try:
                with open(filename, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    # Write header
                    writer.writerow(['Date & Time', 'File', 'Threat Type', 'Action Taken'])
                    
                    # Write data rows
                    for item_id in self.threat_history_treeview.get_children():
                        values = self.threat_history_treeview.item(item_id, 'values')
                        writer.writerow(values)
                
                messagebox.showinfo("Export Successful", f"Threat history exported to {filename}", parent=self.window)
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {str(e)}", parent=self.window)

# Main execution block
if __name__ == "__main__":
    # Create the root window
    root = tk.Tk()
    
    # Create and run the application
    app = AntivirusApp(root)
    root.mainloop()

