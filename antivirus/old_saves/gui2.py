import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import threading
import signal
from datetime import datetime
from PIL import Image, ImageTk

# Global variables
process_rtm = None
file_path = ""

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

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureShield Antivirus")
        self.root.geometry("1440x900")
        self.root.configure(bg=COLORS["bg_dark"])
        self.root.minsize(1200, 800)  # Set minimum size
        
        # Configure ttk styles
        self.setup_styles()
        
        # Set up the main layout
        self.setup_layout()
        
        # Configure tags for the RTM logs
        self.setup_text_tags()
        
        # Paths to executables
        self.engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine")
        self.rtm_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rtm")
        
        # Make executables... executable
        for path in [self.engine_path, self.rtm_path]:
            if os.path.exists(path) and not os.access(path, os.X_OK):
                os.chmod(path, 0o755)
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_styles(self):
        """Configure ttk styles for the application"""
        self.style = ttk.Style()
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
            logo_img = Image.open("images/logo.png")
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
                               command=self.open_password_manager)
        btn_password.pack(fill=tk.X, pady=5)
        
        # Separator
        ttk.Separator(self.sidebar, orient='horizontal').pack(fill=tk.X, padx=20, pady=15)
        
        # Status display
        status_frame = ttk.Frame(self.sidebar)
        status_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(status_frame, text="Protection Status", style='Subtitle.TLabel').pack(anchor=tk.W)
        
        # RTM status indicator
        self.rtm_status_var = tk.StringVar(value="Inactive")
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
        
        # Quick action buttons
        action_frame = ttk.Frame(self.content_area)
        action_frame.pack(fill=tk.X, padx=30, pady=10)
        
        # Use a grid layout for the action cards
        action_frame.columnconfigure(0, weight=1)
        action_frame.columnconfigure(1, weight=1)
        action_frame.columnconfigure(2, weight=1)
        action_frame.columnconfigure(3, weight=1)
        
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
        
        # Exceptions Management Card
        exceptions_frame = self.create_action_card(
            action_frame, "Exceptions", 
            "Manage file and directory exceptions",
            "exceptions.png", self.rtm_manager.show_exceptions_manager)
        exceptions_frame.grid(row=0, column=3, padx=10, pady=10, sticky="nsew")
        
        # Separator
        ttk.Separator(self.content_area, orient='horizontal').pack(fill=tk.X, padx=30, pady=15)
        
        # RTM Logs Section (initially hidden)
        self.setup_rtm_logs_section()

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
            img = Image.open(f"images/{icon_name}")
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
                style='Info.TLabel', wraplength=250).pack(anchor=tk.W, pady=10)
        
        # Button at bottom
        action_button = ttk.Button(inner_frame, text=f"Open {title}", 
                                 style="Primary.TButton", command=command)
        action_button.pack(anchor=tk.W, pady=(10, 0))
        
        return frame
    
    def open_file_scanner(self):
        """Open the file scanner dialog"""
        selected_file_path = filedialog.askopenfilename(parent=self.root)
        if selected_file_path:
            self.scan_file(selected_file_path)
    
    def open_directory_scanner(self):
        """Open the directory scanner dialog"""
        selected_dir_path = filedialog.askdirectory(parent=self.root)
        if selected_dir_path:
            self.scan_directory(selected_dir_path)
    
    def scan_file(self, selected_file_path):
        """Scan a single file for threats"""
        # Create a pop-up window for scan results
        scan_window = tk.Toplevel(self.root)
        scan_window.title("File Scan")
        scan_window.geometry("800x600")
        scan_window.configure(bg=COLORS["bg_dark"])
        scan_window.transient(self.root)  # Make it appear on top of root
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
        
        progress = ttk.Progressbar(progress_frame, orient="horizontal", length=700, mode="indeterminate")
        progress.pack(fill=tk.X)
        progress.start()
        
        # Results text widget
        results_frame = ttk.Frame(scan_window)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        results_text = tk.Text(results_frame, wrap='word',
                             font=('Segoe UI', 10),
                             bg=COLORS["bg_medium"],
                             fg=COLORS["text"],
                             border=0)
        results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=results_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        results_text.config(yscrollcommand=scrollbar.set)
        
        # Apply tags to the results text widget
        for tag_name, properties in {
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
            "normal": {"foreground": COLORS["text"]}
        }.items():
            results_text.tag_configure(tag_name, **properties)
        
        # Initial message
        results_text.insert(tk.END, f"Starting scan of: {selected_file_path}\n", "header")
        
        # Button frame
        button_frame = ttk.Frame(scan_window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        close_button = ttk.Button(button_frame, text="Close", style="Secondary.TButton",
                                command=lambda: self.close_scan_window(scan_window))
        close_button.pack(side=tk.RIGHT)
        
        # Execute the scan in a separate thread
        def scan_thread():
            detection_files = set()
            file_threats = {}
            
            try:
                # Execute engine and capture output
                process = subprocess.Popen(
                    [self.engine_path, selected_file_path], 
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
                        # Process the output line directly in the thread
                        if output_line.startswith("[R]"):
                            result_line = output_line[4:].strip()  # Remove "[R] " prefix
                            parts = result_line.split(":", 3)  # Split by first 3 colons
                            
                            if len(parts) >= 1:
                                timestamp = self.get_timestamp()
                                
                                if parts[0] == "SCAN_START":
                                    # Already showed start message
                                    pass
                                elif parts[0] == "SCAN_COMPLETE":
                                    def update_ui():
                                        results_text.insert(tk.END, f"✅ Scan completed\n", "scan_complete")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                                elif parts[0] == "SAFE" and len(parts) >= 2:
                                    safe_path = parts[1]
                                    def update_ui(path=safe_path):
                                        results_text.insert(tk.END, f"✅ File is safe: {os.path.basename(path)}\n", "safe")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                                elif parts[0] == "DETECTION" and len(parts) >= 3:
                                    detected_path = parts[2]
                                    rule_name = parts[1]
                                    
                                    # Track this file and its threats
                                    if detected_path not in file_threats:
                                        file_threats[detected_path] = []
                                    file_threats[detected_path].append(rule_name)
                                    detection_files.add(detected_path)
                                    
                                    def update_ui(path=detected_path, rule=rule_name, time=timestamp):
                                        results_text.insert(tk.END, f"{time} ⚠️ DETECTION: Rule '{rule}' in {os.path.basename(path)}\n", "detection")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                                elif parts[0] == "UNSAFE" and len(parts) >= 4:
                                    unsafe_path = parts[1]
                                    threats_count = parts[2]
                                    threats = parts[3]
                                    
                                    def update_ui(path=unsafe_path, count=threats_count, t_list=threats, time=timestamp):
                                        results_text.insert(tk.END, f"{time} ❌ UNSAFE: Found {count} threat(s) in {os.path.basename(path)}\n", "unsafe")
                                        results_text.insert(tk.END, f"   Matched rules: {t_list}\n", "unsafe_details")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                                    
                                    # Track this file
                                    detection_files.add(unsafe_path)
                                    
                                    # Track threats
                                    if unsafe_path not in file_threats:
                                        file_threats[unsafe_path] = threats.split(", ")
                                elif parts[0] == "FILE_SCANNING" and len(parts) >= 2:
                                    scan_file = parts[1]
                                    def update_ui(file=scan_file):
                                        results_text.insert(tk.END, f"Scanning: {os.path.basename(file)}\n", "info")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                
                # Stop the progress bar when done
                scan_window.after(0, progress.stop)
                
                # Show summary
                # Replace the part in scan_file function where summary is shown
                # Around line 553, replace the add_summary function with this:

                def add_summary():
                    if file_threats:
                        results_text.insert(tk.END, "\n📊 SCAN SUMMARY:\n", "header")
                        for filepath, threats in file_threats.items():
                            threat_list = ", ".join(threats)
                            results_text.insert(tk.END, f"❌ {os.path.basename(filepath)}: {threat_list}\n", "unsafe")
                        scan_window.title(f"File Scan - Threats Found! ({len(file_threats)})")
                        
                        # Use after() to schedule threat alert on the main thread
                        scan_window.after(500, lambda: display_threat_alert(selected_file_path, file_threats[selected_file_path]))
                    else:
                        results_text.insert(tk.END, "\n✅ No threats detected.\n", "safe")
                        scan_window.title("File Scan - No Threats Found")
                        
                        # Schedule safe notification on the main thread
                        scan_window.after(500, display_safe_notification)
                    
                # Add these helper functions right after the add_summary function
                def display_threat_alert(path, threats):
                    scan_window.grab_release()  # Release grab so alert can show
                    self.show_threat_alert(path, threats)
                    scan_window.grab_set()  # Re-grab after alert is closed

                def display_safe_notification():
                    scan_window.grab_release()
                    messagebox.showinfo(
                        "Scan Complete", 
                        f"✅ The file is safe!\n\nNo threats were detected in:\n{os.path.basename(selected_file_path)}",
                        parent=scan_window
                    )
                    scan_window.grab_set()

                # Add this after the add_summary function in the scan thread
                scan_window.after(0, add_summary)
                
            except Exception as e:
                def show_error(error=str(e)):
                    results_text.insert(tk.END, f"Error: {error}\n", "error")
                    progress.stop()
                scan_window.after(0, show_error)
        
        # Start the thread
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def close_scan_window(self, window):
        """Properly close a scan window by releasing grab and destroying it"""
        window.grab_release()
        window.destroy()
    
    def scan_directory(self, selected_dir_path):
        """Scan a directory for threats"""
        # Create a pop-up window for scan results
        scan_window = tk.Toplevel(self.root)
        scan_window.title("Directory Scan")
        scan_window.geometry("800x600")
        scan_window.configure(bg=COLORS["bg_dark"])
        scan_window.transient(self.root)  # Make it appear on top of root
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
        
        progress = ttk.Progressbar(progress_frame, orient="horizontal", length=700, mode="indeterminate")
        progress.pack(fill=tk.X)
        progress.start()
        
        # Results text widget
        results_frame = ttk.Frame(scan_window)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        results_text = tk.Text(results_frame, wrap='word',
                             font=('Segoe UI', 10),
                             bg=COLORS["bg_medium"],
                             fg=COLORS["text"],
                             border=0)
        results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=results_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        results_text.config(yscrollcommand=scrollbar.set)
        
        # Apply tags to the results text widget
        for tag_name, properties in {
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
            "normal": {"foreground": COLORS["text"]}
        }.items():
            results_text.tag_configure(tag_name, **properties)
        
        # Initial message
        results_text.insert(tk.END, f"Starting scan of directory: {selected_dir_path}\n", "header")
        results_text.insert(tk.END, "This may take some time for large directories...\n", "info")
        
        # Button frame
        button_frame = ttk.Frame(scan_window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        close_button = ttk.Button(button_frame, text="Close", style="Secondary.TButton",
                                command=lambda: self.close_scan_window(scan_window))
        close_button.pack(side=tk.RIGHT)
        
        # Execute the directory scan in a thread
        def scan_thread():
            detection_files = set()
            file_threats = {}
            
            try:
                # Execute engine with directory path
                process = subprocess.Popen(
                    [self.engine_path, selected_dir_path], 
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
                        # Process the output line directly in the thread
                        if output_line.startswith("[R]"):
                            result_line = output_line[4:].strip()  # Remove "[R] " prefix
                            parts = result_line.split(":", 3)  # Split by first 3 colons
                            
                            if len(parts) >= 1:
                                timestamp = self.get_timestamp()
                                
                                if parts[0] == "SCAN_START":
                                    # Already showed start message
                                    pass
                                elif parts[0] == "SCAN_COMPLETE":
                                    def update_ui():
                                        results_text.insert(tk.END, f"✅ Scan completed\n", "scan_complete")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                                elif parts[0] == "SAFE" and len(parts) >= 2:
                                    safe_path = parts[1]
                                    def update_ui(path=safe_path):
                                        results_text.insert(tk.END, f"✅ File is safe: {os.path.basename(path)}\n", "safe")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                                elif parts[0] == "DETECTION" and len(parts) >= 3:
                                    detected_path = parts[2]
                                    rule_name = parts[1]
                                    
                                    # Track this file and its threats
                                    if detected_path not in file_threats:
                                        file_threats[detected_path] = []
                                    file_threats[detected_path].append(rule_name)
                                    detection_files.add(detected_path)
                                    
                                    def update_ui(path=detected_path, rule=rule_name, time=timestamp):
                                        results_text.insert(tk.END, f"{time} ⚠️ DETECTION: Rule '{rule}' in {os.path.basename(path)}\n", "detection")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                                elif parts[0] == "UNSAFE" and len(parts) >= 4:
                                    unsafe_path = parts[1]
                                    threats_count = parts[2]
                                    threats = parts[3]
                                    
                                    def update_ui(path=unsafe_path, count=threats_count, t_list=threats, time=timestamp):
                                        results_text.insert(tk.END, f"{time} ❌ UNSAFE: Found {count} threat(s) in {os.path.basename(path)}\n", "unsafe")
                                        results_text.insert(tk.END, f"   Matched rules: {t_list}\n", "unsafe_details")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                                    
                                    # Track this file
                                    detection_files.add(unsafe_path)
                                    
                                    # Track threats
                                    if unsafe_path not in file_threats:
                                        file_threats[unsafe_path] = threats.split(", ")
                                elif parts[0] == "FILE_SCANNING" and len(parts) >= 2:
                                    scan_file = parts[1]
                                    def update_ui(file=scan_file):
                                        results_text.insert(tk.END, f"Scanning: {os.path.basename(file)}\n", "info")
                                        results_text.see(tk.END)
                                    scan_window.after(0, update_ui)
                
                # Stop the progress bar when done
                scan_window.after(0, progress.stop)
                
                # Show summary
                # Around line 720, replace the add_summary function in scan_directory with:
                def add_summary():
                    if file_threats:
                        results_text.insert(tk.END, "\n📊 SCAN SUMMARY:\n", "header")
                        for filepath, threats in file_threats.items():
                            threat_list = ", ".join(threats)
                            results_text.insert(tk.END, f"❌ {os.path.basename(filepath)}: {threat_list}\n", "unsafe")
                        scan_window.title(f"Directory Scan - Threats Found! ({len(file_threats)})")
                        
                        # Schedule the summary alert on the main thread
                        scan_window.after(500, show_summary_alert)
                        
                    else:
                        results_text.insert(tk.END, "\n✅ No threats detected in any files.\n", "safe")
                        scan_window.title("Directory Scan - No Threats Found")
                        
                        # Schedule safe notification on the main thread
                        scan_window.after(500, show_safe_dir_notification)

                def show_summary_alert():
                    scan_window.grab_release()
                    if messagebox.askyesno(
                        "Threats Detected", 
                        f"⚠️ Found threats in {len(file_threats)} files!\n\nDo you want to see details for each infected file?",
                        parent=scan_window
                    ):
                        # Show alert for each infected file
                        for filepath, threats in file_threats.items():
                            self.show_threat_alert(filepath, threats)
                    scan_window.grab_set()

                def show_safe_dir_notification():
                    scan_window.grab_release()
                    messagebox.showinfo(
                        "Scan Complete", 
                        f"✅ Directory is safe!\n\nNo threats were detected in:\n{selected_dir_path}",
                        parent=scan_window
                    )
                    scan_window.grab_set()

                # Add this after the add_summary function in the scan thread
                scan_window.after(0, add_summary)


            except Exception as e:
                def show_error(error=str(e)):
                    results_text.insert(tk.END, f"Error: {error}\n", "error")
                    progress.stop()
                scan_window.after(0, show_error)
        
        # Start the thread
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def process_scan_output(self, output_line, text_widget, detection_files, file_threats):
        """Process a line of output from the scanning engine"""
        # Only process result lines that start with [R]
        if output_line.startswith("[R]"):
            # Parse result lines
            result_line = output_line[4:].strip()  # Remove "[R] " prefix
            parts = result_line.split(":", 3)  # Split by first 3 colons
            
            if len(parts) > 0:
                if parts[0] == "SCAN_START":
                    # Don't show multiple scan start messages
                    pass
                elif parts[0] == "SCAN_COMPLETE":
                    # Only show scan completion if files were scanned
                    if detection_files:
                        # Show a summary instead of individual file completions
                        text_widget.insert(tk.END, f"\n✅ Scan completed: Found threats in {len(detection_files)} files\n", "header")
                    else:
                        text_widget.insert(tk.END, f"✅ Scan completed: All files are clean\n", "safe")
                elif parts[0] == "SAFE":
                    # Optionally show safe files (could be toggled by a setting)
                    text_widget.insert(tk.END, f"✅ File is safe: {os.path.basename(parts[1])}\n", "safe")
                elif parts[0] == "DETECTION":
                    path = parts[2]
                    rule_name = parts[1]
                    
                    # Track this file and its threats
                    if path not in file_threats:
                        file_threats[path] = []
                    file_threats[path].append(rule_name)
                    detection_files.add(path)
                    
                    # Show detection with timestamp for better tracking
                    timestamp = self.get_timestamp()
                    text_widget.insert(tk.END, f"{timestamp} ⚠️ DETECTION: Rule '{rule_name}' in {os.path.basename(path)}\n", "detection")
                elif parts[0] == "UNSAFE" and len(parts) >= 4:
                    path = parts[1]
                    threats_count = parts[2]
                    threats = parts[3]
                    
                    timestamp = self.get_timestamp()
                    text_widget.insert(tk.END, f"{timestamp} ❌ UNSAFE: Found {threats_count} threat(s) in {os.path.basename(path)}\n", "unsafe")
                    text_widget.insert(tk.END, f"   Matched rules: {threats}\n", "unsafe_details")
                    
                    # Track this file
                    detection_files.add(path)
                    
                    # Track threats
                    if path not in file_threats:
                        file_threats[path] = threats.split(", ")
                elif parts[0] == "FILE_SCANNING":
                    # Show which file is being scanned
                    text_widget.insert(tk.END, f"Scanning: {os.path.basename(parts[1])}\n", "info")
                else:
                    # Unknown result type - don't display
                    pass
                
                # Auto-scroll to see the latest entries
                text_widget.see(tk.END)



    def show_threat_alert(self, file_path, threats):
        """Show a user-friendly alert when threats are detected with options to delete or view details"""
        # Create alert window
        alert_window = tk.Toplevel(self.root)
        alert_window.title("⚠️ Threat Detected!")
        alert_window.geometry("500x300")
        alert_window.configure(bg=COLORS["bg_dark"])
        alert_window.transient(self.root)  # Make it appear on top of root
        
        # Add some warning styling
        alert_window.attributes('-topmost', True)
        
        # Warning icon and header
        header_frame = ttk.Frame(alert_window)
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Try to load warning icon
        try:
            img = Image.open("images/warning.png")
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
        content_frame = ttk.Frame(alert_window)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # File information
        ttk.Label(content_frame, 
                text=f"The following file has been identified as potentially harmful:",
                style='Subtitle.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        # File path (with filename in bold)
        file_name = os.path.basename(file_path)
        file_dir = os.path.dirname(file_path)
        
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
        threat_count = len(threats) if isinstance(threats, list) else 1
        ttk.Label(content_frame, 
                text=f"Found {threat_count} security {'threat' if threat_count == 1 else 'threats'}.",
                style='Subtitle.TLabel', 
                foreground=COLORS["warning"]).pack(anchor=tk.W, pady=10)
        
        # Buttons frame
        button_frame = ttk.Frame(alert_window)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        def delete_file():
            try:
                # Delete the file
                os.remove(file_path)
                # Update alert to show success
                for widget in button_frame.winfo_children():
                    widget.destroy()
                
                ttk.Label(button_frame, text="✅ File successfully deleted!", 
                        foreground=COLORS["success"],
                        font=('Segoe UI', 11, 'bold')).pack(side=tk.LEFT)
                
                # Add close button
                ttk.Button(button_frame, text="Close", style="Secondary.TButton",
                        command=alert_window.destroy).pack(side=tk.RIGHT)
                
            except Exception as e:
                # Show error if deletion fails
                messagebox.showerror("Deletion Error", f"Could not delete file: {str(e)}", parent=alert_window)
        
        def show_details():
            # Create details window
            details_window = tk.Toplevel(alert_window)
            details_window.title("Threat Details")
            details_window.geometry("600x400")
            details_window.configure(bg=COLORS["bg_dark"])
            details_window.transient(alert_window)
            
            # Details header
            ttk.Label(details_window, text="Detailed Threat Information", 
                    style='Title.TLabel').pack(padx=20, pady=10)
            
            # File path information
            path_frame = ttk.Frame(details_window)
            path_frame.pack(fill=tk.X, padx=20, pady=5)
            
            ttk.Label(path_frame, text="File:", 
                    style='Info.TLabel', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
            ttk.Label(path_frame, text=file_path, 
                    style='Info.TLabel').pack(side=tk.LEFT, padx=5)
            
            # Detected rules section
            ttk.Label(details_window, text="Matched Security Rules:", 
                    style='Subtitle.TLabel').pack(anchor=tk.W, padx=20, pady=10)
            
            # Rules display
            rules_frame = ttk.Frame(details_window)
            rules_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            
            # Use Treeview to show rules in a nice table
            columns = ('rule_id', 'description', 'severity')
            rules_treeview = ttk.Treeview(rules_frame, columns=columns, show='headings')
            
            # Define headings
            rules_treeview.heading('rule_id', text='Rule ID')
            rules_treeview.heading('description', text='Description')
            rules_treeview.heading('severity', text='Severity')
            
            # Define column widths
            rules_treeview.column('rule_id', width=100)
            rules_treeview.column('description', width=350)
            rules_treeview.column('severity', width=100)
            
            # Add a scrollbar
            scrollbar = ttk.Scrollbar(rules_frame, orient=tk.VERTICAL, command=rules_treeview.yview)
            rules_treeview.configure(yscroll=scrollbar.set)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            rules_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Insert rule data
            if isinstance(threats, list):
                for i, rule in enumerate(threats):
                    # For each rule name, you could lookup its description and severity
                    # from a predefined dictionary if available
                    rules_treeview.insert('', tk.END, values=(rule, f"Detected threat pattern: {rule}", "High"))
            else:
                # Handle case where threats is a string
                rules_treeview.insert('', tk.END, values=(threats, f"Detected threat pattern: {threats}", "High"))
            
            # Bottom buttons
            btn_frame = ttk.Frame(details_window)
            btn_frame.pack(fill=tk.X, padx=20, pady=20)
            
            ttk.Button(btn_frame, text="Close", style="Secondary.TButton",
                    command=details_window.destroy).pack(side=tk.RIGHT)
        
        # Action buttons
        delete_btn = ttk.Button(button_frame, text="Delete File", style="Primary.TButton",
                            command=delete_file)
        delete_btn.pack(side=tk.LEFT)
        
        details_btn = ttk.Button(button_frame, text="View Details", style="Secondary.TButton",
                            command=show_details)
        details_btn.pack(side=tk.LEFT, padx=10)
        
        ignore_btn = ttk.Button(button_frame, text="Ignore", style="Secondary.TButton",
                            command=alert_window.destroy)
        ignore_btn.pack(side=tk.RIGHT)


    def show_safe_alert(self, file_path):
        """Show a user-friendly alert for safe files"""
        messagebox.showinfo(
            "✅ File is Safe", 
            f"No threats were detected in:\n{file_path}",
            parent=self.root
        )


    def show_rtm_config(self):
        """Show RTM configuration window"""
        # Create a pop-up window for RTM configuration
        rtm_window = tk.Toplevel(self.root)
        rtm_window.title("Real-Time Monitoring Configuration")
        rtm_window.geometry("800x600")
        rtm_window.configure(bg=COLORS["bg_dark"])
        
        # Make this window appear on top and be modal
        rtm_window.transient(self.root)  # Make it appear on top of root
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
        
        # Fixed browse directory function
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
        
        # If RTM is already running, update the UI
        if process_rtm and process_rtm.poll() is None:
            self.rtm_status_label.config(text="Active", foreground=COLORS["success"])
            self.rtm_button.config(text="Disable Protection")
            
            # Also update main window status
            self.rtm_status_var.set("Active")
            self.rtm_status_indicator.config(fg=COLORS["success"])
    
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
            self.rtm_status_var.set("Inactive")
            self.rtm_status_indicator.config(fg=COLORS["error"])
            
            # Log message
            self.output_text_rtm.insert(tk.END, f"{self.get_timestamp()} ⏹️ Real-time monitoring stopped\n", "normal")
            self.output_text_rtm.see(tk.END)
            
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
            self.output_text_rtm.delete(1.0, tk.END)
            
            # Update status
            self.rtm_status_label.config(text="Starting...", foreground=COLORS["warning"])
            self.rtm_status_var.set("Starting...")
            self.rtm_status_indicator.config(fg=COLORS["warning"])
            
            # Log message
            timestamp = self.get_timestamp()
            self.output_text_rtm.insert(tk.END, f"{timestamp} 🔍 REAL-TIME MONITORING STARTING\n", "header")
            self.output_text_rtm.insert(tk.END, f"Monitoring directories: {directories}\n\n", "scan_start")
            
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
            self.rtm_status_var.set("Active")
            self.rtm_status_indicator.config(fg=COLORS["success"])
            
        except Exception as e:
            # Release grab for messagebox
            parent_window.grab_release()
            messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}", parent=parent_window)
            parent_window.grab_set()
            self.output_text_rtm.insert(tk.END, f"Error starting RTM: {str(e)}\n", "error")
    
    def read_rtm_output(self):
        """Read and process output from the RTM process"""
        global process_rtm
        
        if not process_rtm:
            return
        
        # This set will prevent showing duplicate detections for the same file
        detected_files = set()
        file_threats = {}  # Track threats for each file
        
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
                            timestamp = self.get_timestamp()
                            
                            # Track threats for this file
                            if detected_path not in file_threats:
                                file_threats[detected_path] = []
                            file_threats[detected_path].append(rule_name)
                            
                            # Fixed method to avoid lambda issues
                            def show_detection(p=detected_path, r=rule_name, t=timestamp):
                                self.output_text_rtm.insert(tk.END, f"{t} ⚠️ DETECTION: Rule '{r}' matched in {p}\n", "detection")
                                self.output_text_rtm.see(tk.END)
                            
                            self.root.after(0, show_detection)
                            
                        elif parts[0] == "UNSAFE" and len(parts) >= 4:
                            unsafe_path = parts[1]
                            threat_count = parts[2]
                            threats = parts[3]
                            timestamp = self.get_timestamp()
                            
                            # Only show alert if this is the first time seeing this file
                            if unsafe_path not in detected_files:
                                detected_files.add(unsafe_path)
                                
                                # Show alert for this file
                                def show_rtm_alert(path=unsafe_path, threat_list=threats.split(", ")):
                                    self.root.after_idle(lambda p=path, tl=threat_list: self.show_threat_alert(p, tl))                                
                                # Schedule alert to show after logging
                                self.root.after(100, show_rtm_alert)
                            
                            # Update threats for this file
                            file_threats[unsafe_path] = threats.split(", ")
                            
                            # Fixed method to avoid lambda issues
                            def show_unsafe(p=unsafe_path, c=threat_count, t_rules=threats, t=timestamp):
                                self.output_text_rtm.insert(tk.END, f"{t} ❌ UNSAFE: Found {c} threat(s) in {p}\n", "unsafe")
                                self.output_text_rtm.insert(tk.END, f"   Matched rules: {t_rules}\n", "unsafe_details")
                                self.output_text_rtm.see(tk.END)
                            
                            self.root.after(0, show_unsafe)
                        
                        # ... rest of your existing code for other event types ...
                            
                        elif parts[0] == "FILE_MODIFIED":
                            timestamp = self.get_timestamp()
                            modified_path = parts[1]
                            
                            def show_modified(p=modified_path, t=timestamp):
                                self.output_text_rtm.insert(tk.END, f"{t} 🔄 FILE MODIFIED: {p}\n", "change")
                                self.output_text_rtm.see(tk.END)
                            
                            self.root.after(0, show_modified)
                            
                        elif parts[0] == "FILE_CREATED":
                            timestamp = self.get_timestamp()
                            created_path = parts[1]
                            
                            def show_created(p=created_path, t=timestamp):
                                self.output_text_rtm.insert(tk.END, f"{t} ➕ FILE CREATED: {p}\n", "created")
                                self.output_text_rtm.see(tk.END)
                            
                            self.root.after(0, show_created)
                            
                        elif parts[0] == "FILE_DELETED":
                            timestamp = self.get_timestamp()
                            deleted_path = parts[1]
                            
                            def show_deleted(p=deleted_path, t=timestamp):
                                self.output_text_rtm.insert(tk.END, f"{t} ➖ FILE DELETED: {p}\n", "deleted")
                                self.output_text_rtm.see(tk.END)
                            
                            self.root.after(0, show_deleted)
                            
                        elif parts[0] == "MONITORING_ACTIVE":
                            timestamp = self.get_timestamp()
                            monitored_path = parts[1]
                            
                            def show_monitoring(p=monitored_path, t=timestamp):
                                self.output_text_rtm.insert(tk.END, f"{t} 🔍 MONITORING ACTIVE: {p}\n", "monitoring")
                                self.output_text_rtm.see(tk.END)
                            
                            self.root.after(0, show_monitoring)
                        else:
                            # Unknown result type - don't display
                            pass
    
    def open_password_manager(self):
        """Open the password manager application"""
        try:
            password_manager_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pm", "password_manager_gui.py")
            
            if not os.path.exists(password_manager_path):
                messagebox.showerror("Error", f"Password manager not found at {password_manager_path}")
                return
            
            # Start the password manager in a separate process
            subprocess.Popen(["python3", password_manager_path])
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open password manager: {str(e)}")
    
    def clear_logs(self):
        """Clear the RTM logs"""
        self.output_text_rtm.delete(1.0, tk.END)
        self.output_text_rtm.insert(tk.END, "Logs cleared.\n", "info")
    
    def get_timestamp(self):
        """Get a formatted timestamp for logging"""
        return datetime.now().strftime("%H:%M:%S")
    
    def on_closing(self):
        """Handle window closing event"""
        global process_rtm
        
        # Ask for confirmation
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
        
        # Close the window
        self.root.destroy()

if __name__ == "__main__":
    # Create the root window
    root = tk.Tk()
    
    # Create and run the application
    app = AntivirusApp(root)
    root.mainloop()