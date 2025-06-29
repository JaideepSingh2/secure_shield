from tkinter import *
from tkinter import filedialog
import subprocess
import os
from PIL import Image, ImageTk
import threading
import signal

# Global variables
process_rtm = None
file_path = ""

root = Tk()
root.title("Antivirus Software")
root.geometry("1440x900")
root.resizable(0,0)
root.configure(bg="#262626")

def open_file():
    global file_path
    file_path = filedialog.askopenfilename()
    if file_path:
        file_label.config(text="Chosen path: " + file_path)
    else:
        file_label.config(text="No path selected")

def open_directory():
    global file_path
    file_path = filedialog.askdirectory()
    if file_path:
        file_label.config(text="Chosen path: " + file_path)
    else:
        file_label.config(text="No path selected")

def execute_engine(file_path, output_text):
    if file_path:
        try:
            # Execute engine and capture output
            output_text.delete(1.0, END)  # Clear previous output
            file_label.config(text=f"Scanning: {file_path}")
            
            # Use full path to the engine
            engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine")
            
            # Ensure the engine is executable
            if not os.path.exists(engine_path):
                output_text.insert(END, f"Error: Engine not found at {engine_path}\n")
                return
                
            if not os.access(engine_path, os.X_OK):
                os.chmod(engine_path, 0o755)  # Make executable if it's not
                
            process = subprocess.Popen([engine_path, file_path], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       universal_newlines=True)
            
            # Read output line by line in a separate thread
            def read_output():
                while True:
                    output_line = process.stdout.readline()
                    if not output_line and process.poll() is not None:
                        break
                    if output_line:
                        output_text.insert(END, output_line)
                        output_text.see(END)
                        root.update_idletasks()  # Update the GUI
                
                # Read any error output
                for error_line in process.stderr:
                    output_text.insert(END, f"Error: {error_line}")
                    output_text.see(END)
                    
                return_code = process.wait()
                if return_code != 0:
                    output_text.insert(END, f"Process exited with code {return_code}\n")
                    
                file_label.config(text=f"Scan completed: {file_path}")
            
            # Start reading in a separate thread
            threading.Thread(target=read_output, daemon=True).start()
        except Exception as e:
            output_text.insert(END, f"Error: {str(e)}\n")
    else:
        file_label.config(text="No path selected")

def execute_engine_rtm(directory_paths, output_text):
    global process_rtm
    
    if not directory_paths:
        file_label.config(text="No directories selected for monitoring")
        output_text.insert(END, "Error: No directories selected for monitoring\n", "error")
        return
    
    try:
        # Kill any existing RTM process
        if process_rtm and process_rtm.poll() is None:
            process_rtm.terminate()
            try:
                process_rtm.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process_rtm.kill()
        
        # Clear the output
        output_text.delete(1.0, END)
        
        # Use full path to the rtm executable
        rtm_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rtm")
        
        # Ensure rtm is executable
        if not os.path.exists(rtm_path):
            output_text.insert(END, f"Error: RTM executable not found at {rtm_path}\n", "error")
            return
            
        if not os.access(rtm_path, os.X_OK):
            os.chmod(rtm_path, 0o755)  # Make executable if it's not
            
        # Start the rtm process with the selected directories
        output_text.insert(END, f"Starting real-time monitoring for: {directory_paths}\n", "normal")
        output_text.insert(END, "First performing initial scan of directories to check existing files...\n", "scan_start")
        file_label.config(text=f"Monitoring: {directory_paths}")
        
        # Apply all text tags
        setup_text_tags(output_text)
        
        process_rtm = subprocess.Popen([rtm_path, directory_paths], 
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, 
                                      universal_newlines=True,
                                      bufsize=1)  # Line buffered
        
        # Read output in a separate thread
        def read_rtm_output():
            while process_rtm and process_rtm.poll() is None:
                output_line = process_rtm.stdout.readline()
                if not output_line and process_rtm.poll() is not None:
                    break
                if output_line:
                    # Apply color coding for different message types
                    if "File deleted:" in output_line:
                        output_text.insert(END, output_line, "deletion")
                    elif "Initial scan of file:" in output_line:
                        output_text.insert(END, output_line, "initial_scan")
                    elif "Initial scan of directory completed:" in output_line or "Initial scan completed for directory:" in output_line:
                        output_text.insert(END, output_line, "scan_complete")
                    elif "Performing initial scan" in output_line or "Starting initial scan" in output_line or "STARTING INITIAL SCAN" in output_line:
                        output_text.insert(END, output_line, "scan_start")
                    elif "Matched rule:" in output_line:
                        output_text.insert(END, output_line, "detection")
                    elif "Now monitoring directory" in output_line or "Monitoring directory:" in output_line or "Now actively monitoring" in output_line:
                        output_text.insert(END, output_line, "monitoring")
                    elif "Successfully compiled rules" in output_line or "Compiled rules" in output_line:
                        output_text.insert(END, output_line, "scan_complete")
                    elif "COMPLETED INITIAL SCAN" in output_line:
                        output_text.insert(END, output_line, "scan_complete")
                    else:
                        output_text.insert(END, output_line, "normal")
                    
                    # Ensure the output automatically scrolls to show latest entries
                    output_text.see(END)
                    root.update_idletasks()  # Update the GUI
            
            # Read any error output
            if process_rtm:
                for error_line in process_rtm.stderr:
                    output_text.insert(END, f"Error: {error_line}", "error")
                    output_text.see(END)
                
                if process_rtm.poll() is not None:
                    output_text.insert(END, f"RTM process exited with code {process_rtm.returncode}\n")
        
        # Start reading in a separate thread
        threading.Thread(target=read_rtm_output, daemon=True).start()
        
    except Exception as e:
        output_text.insert(END, f"Error starting RTM: {str(e)}\n", "error")

def toggle_win():
    menu = Frame(root,width=300,height=900,bg="#12c4c0")
    menu.place(x=0,y=0)

    home_button = Button(menu, text="Home", command=show_root, width=42, height=3, 
                      fg="#262626", bg="#0f9d9a", activebackground="#12c4c0", activeforeground="#262626", border=0)
    home_button.place(x=0, y=80)

    File_button = Button(menu, text="File Upload", command=show_file_upload_page, width=42, height=3, 
                      fg="#262626", bg="#0f9d9a", activebackground="#12c4c0", activeforeground="#262626", border=0)
    File_button.place(x=0, y=140)

    Dir_button = Button(menu, text="Directory Upload", command=show_directory_upload_page, width=42, height=3, 
                     fg="#262626", bg="#0f9d9a", activebackground="#12c4c0", activeforeground="#262626", border=0)
    Dir_button.place(x=0, y=200)

    rlmonitor_button = Button(menu, text="Real-Time Monitoring", command=show_rtm_page, width=42, height=3, 
                           fg="#262626", bg="#0f9d9a", activebackground="#12c4c0", activeforeground="#262626", border=0)
    rlmonitor_button.place(x=0, y=260)

    # Adding the password manager button
    password_manager_button = Button(menu, text="Password Manager", command=open_password_manager, width=42, height=3, 
                                fg="#262626", bg="#0f9d9a", activebackground="#12c4c0", activeforeground="#262626", border=0)
    password_manager_button.place(x=0, y=320)

    def dele():
        File_button.destroy()
        Dir_button.destroy()
        rlmonitor_button.destroy()
        password_manager_button.destroy()
        menu.destroy()
    
    global menu_close
    tmp_pic = Image.open("images/menu_close.png")
    resized_tmp_pic = tmp_pic.resize((50, 50), Image.LANCZOS)
    menu_close = ImageTk.PhotoImage(resized_tmp_pic)

    Button(menu, image=menu_close, command=dele, border=0, activebackground="#12c4c0",bg='#12c4c0').place(x=5,y=10)

def open_password_manager():
    try:
        password_manager_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pm", "password_manager_gui.py")
        
        if not os.path.exists(password_manager_path):
            print(f"Error: Password manager not found at {password_manager_path}")
            return
        
        # Start the password manager in a separate process
        subprocess.Popen(["python3", password_manager_path])
        
    except Exception as e:
        print(f"Error opening password manager: {e}")

def show_root():
    rtm_notif_on_root.pack()
    file_upload_page.pack_forget()
    directory_upload_page.pack_forget()
    rtm_page.pack_forget()

def show_file_upload_page():
    file_upload_page.pack()
    directory_upload_page.pack_forget()
    rtm_page.pack_forget()
    rtm_notif_on_root.pack_forget()

def show_directory_upload_page():
    file_upload_page.pack_forget()
    directory_upload_page.pack()
    rtm_page.pack_forget()
    rtm_notif_on_root.pack_forget()

def show_rtm_page():
    file_upload_page.pack_forget()
    directory_upload_page.pack_forget()
    rtm_page.pack()
    rtm_notif_on_root.pack_forget()

def toggle_switch():
    global process_rtm
    if switch_var.get() == 1:
        switch_button.config(text="Enabled", fg="#12c4c0")
        directories = ''.join(directory_listbox.get(0, 'end'))
        if not directories:
            output_text_rtm.insert(END, "Error: No directories added for monitoring\n", "error")
            switch_var.set(0)  # Reset the switch
            return
            
        # Show the initial scanning message in both RTM page and home log page
        output_text_rtm.delete(1.0, END)  # Clear the RTM output
        message = f"Starting real-time monitoring with initial scan for: {directories}\n"
        output_text_rtm.insert(END, message, "scan_start")
        
        # Copy RTM output to home page output text widget
        output_text_home = output_text_rtm  # Use the same text widget
            
        execute_engine_rtm(directories, output_text_rtm)
    else:
        switch_button.config(text="Disabled", fg="Black")
        if process_rtm and process_rtm.poll() is None:
            process_rtm.terminate()
            try:
                process_rtm.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process_rtm.kill()
            message = "Real-time monitoring stopped\n"
            output_text_rtm.insert(END, message, "normal")
            
def add_item():
    rtm_dir_path = directory_entry.get()
    if rtm_dir_path:
        # Check if the path exists
        if os.path.isdir(rtm_dir_path):
            directory_listbox.insert(END, rtm_dir_path + ";")
            directory_entry.delete(0, END)
        else:
            output_text_rtm.insert(END, f"Error: Directory doesn't exist: {rtm_dir_path}\n")
    else:
        output_text_rtm.insert(END, "Error: No directory path entered\n")

def delete_item():
    selected_indices = directory_listbox.curselection()
    for index in selected_indices[::-1]:
        directory_listbox.delete(index)

def clear_rtm_output():
    output_text_rtm.delete(1.0, END)

def on_closing():
    # Ensure clean exit by terminating any running processes
    global process_rtm
    if process_rtm and process_rtm.poll() is None:
        process_rtm.terminate()
        try:
            process_rtm.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process_rtm.kill()
    root.destroy()

# Handle window close event
root.protocol("WM_DELETE_WINDOW", on_closing)

# Open toggle menu button
try:
    tmp_pic = Image.open("images/menu_open.png")
    resized_tmp_pic = tmp_pic.resize((50, 50), Image.LANCZOS)
    menu_open = ImageTk.PhotoImage(resized_tmp_pic)
    Button(root, image=menu_open, command=toggle_win, border=0, 
           activebackground="#262626", bg='#262626').place(x=5, y=10)
except Exception as e:
    print(f"Error loading images: {e}")
    # Fallback button if image can't be loaded
    Button(root, text="Menu", command=toggle_win, border=0,
           activebackground="#262626", bg='#262626', fg='white').place(x=5, y=10)

# Pages
file_upload_page = Frame(root, bg="#262626")
rtm_notif_on_root = Frame(root, bg="#262626")
directory_upload_page = Frame(root, bg="#262626")
rtm_page = Frame(root, bg="#262626")

# Add a password manager button directly on the home page
password_button = Button(rtm_notif_on_root, text="Open Password Manager", 
                      command=open_password_manager, border=0, width=20, height=2,
                      bg="#12c4c0", fg="#262626", activebackground="#0f9d9a")
password_button.pack(side=BOTTOM, pady=20)

rtm_notif_on_root.pack()

my_label_rtm = Label(rtm_notif_on_root, text="Real-Time Monitoring logs", font=("Helvetica", 30, "bold"), 
                    bg="#262626", fg="#12c4c0")
my_label_rtm.pack(pady=20)

output_text_rtm = Text(rtm_notif_on_root, width=70, height=10, wrap='word', 
                     font=("Helvetica", 14), border=10, bg="#262626", fg="white")
output_text_rtm.pack(pady=10)

clear_button = Button(rtm_notif_on_root, text="Clear", command=clear_rtm_output, 
                    border=0, width=20, height=3)
clear_button.pack()

# File upload page
my_label = Label(file_upload_page, text="File Scanner", font=("Helvetica", 40, "bold"), 
               bg="#262626", fg="#12c4c0")
my_label.pack(pady=10)

file_label = Label(file_upload_page, text="", font=("Helvetica", 12, "bold"), 
                 bg="#262626", fg="white")
file_label.pack(pady=10)

try:
    upload_image = Image.open("images/upload_image.png")
    upload_image_resized = upload_image.resize((200, 170), Image.LANCZOS)
    upload_image_tk = ImageTk.PhotoImage(upload_image_resized)
    image_button = Label(file_upload_page, image=upload_image_tk)
    image_button.pack(pady=10)
    image_button.bind("<Button-1>", lambda event: open_file())
except Exception as e:
    print(f"Error loading upload image: {e}")
    # Fallback button if image can't be loaded
    image_button = Button(file_upload_page, text="Click to Upload File", 
                         command=open_file, height=5, width=30)
    image_button.pack(pady=10)

my_button = Button(file_upload_page, text="Upload", 
                 command=lambda: execute_engine(file_path, output_text_file), width=28, height=2)
my_button.pack(pady=20)

my_label = Label(file_upload_page, text="Scan results", font=("Helvetica", 30, "bold"), 
               bg="#262626", fg="#12c4c0")
my_label.pack(pady=20)

output_text_file = Text(file_upload_page, width=70, height=10, wrap='word', 
                      font=("Helvetica", 14), border=10, bg="#262626", fg="white")
output_text_file.pack(pady=10)

# Directory upload page
my_label = Label(directory_upload_page, text="Directory Scanner", font=("Helvetica", 40, "bold"), 
               bg="#262626", fg="#12c4c0")
my_label.pack(pady=10)

file_label = Label(directory_upload_page, text="", font=("Helvetica", 12, "bold"), 
                 bg="#262626", fg="white")
file_label.pack(pady=10)

try:
    image_button = Label(directory_upload_page, image=upload_image_tk)
    image_button.pack(pady=10)
    image_button.bind("<Button-1>", lambda event: open_directory())
except:
    # Fallback button if image can't be loaded
    image_button = Button(directory_upload_page, text="Click to Select Directory", 
                         command=open_directory, height=5, width=30)
    image_button.pack(pady=10)

my_button = Button(directory_upload_page, text="Upload", 
                 command=lambda: execute_engine(file_path, output_text_directory), width=28, height=2)
my_button.pack(pady=20)

my_label = Label(directory_upload_page, text="Scan results", font=("Helvetica", 30, "bold"), 
               bg="#262626", fg="#12c4c0")
my_label.pack(pady=20)

output_text_directory = Text(directory_upload_page, width=70, height=10, wrap='word', 
                          font=("Helvetica", 14), border=10, bg="#262626", fg="white")
output_text_directory.pack(pady=10)

# RTM page
my_label = Label(rtm_page, text="Real-Time Monitoring", font=("Helvetica", 40, "bold"), 
               bg="#262626", fg="#12c4c0")
my_label.pack(pady=10)

switch_var = IntVar()
switch_button = Checkbutton(rtm_page, text="Disabled", variable=switch_var, command=toggle_switch, 
                          border=0, font=("Helvetica", 24, "bold"), width=40, indicatoron=False)
switch_button.pack()

my_label = Label(rtm_page, text="Enter directory path here:", font=("Helvetica", 15, "bold"), 
               bg="#262626", fg="White")
my_label.pack(pady=30)

directory_entry = Entry(rtm_page, width=100, bg="#787a79", border=0, font=("Helvetica", 10))
directory_entry.pack()

directory_listbox = Listbox(rtm_page, border=0, width=70, height=10, bg="#787a79", font=("Helvetica", 15))
directory_listbox.pack(pady=30)

button_frame = Frame(rtm_page, bg="#262626")
button_frame.pack()

add_button = Button(button_frame, text="Add", command=add_item, border=0, width=20, height=3)
add_button.pack(side=LEFT)

delete_button = Button(button_frame, text="Delete", command=delete_item, border=0, width=20, height=3)
delete_button.pack(side=LEFT, padx=10)

# Set up tags for both output text widgets
def setup_text_tags(text_widget):
    text_widget.tag_configure("deletion", foreground="red")
    text_widget.tag_configure("initial_scan", foreground="blue")
    text_widget.tag_configure("scan_complete", foreground="green", font=("Helvetica", 14, "bold"))
    text_widget.tag_configure("scan_start", foreground="purple", font=("Helvetica", 14, "bold"))
    text_widget.tag_configure("detection", foreground="orange", font=("Helvetica", 14, "bold"))
    text_widget.tag_configure("normal", foreground="white")
    text_widget.tag_configure("monitoring", foreground="green")
    text_widget.tag_configure("error", foreground="red", background="yellow")

# Apply tags to all text widgets
setup_text_tags(output_text_rtm)
setup_text_tags(output_text_file)
setup_text_tags(output_text_directory)

# Start the main loop
root.mainloop()