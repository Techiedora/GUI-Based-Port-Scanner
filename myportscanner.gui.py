#!/usr/bin/python3

import socket
from threading import Thread, Lock
import tkinter as tk
from tkinter import scrolledtext, messagebox

open_ports = []
lock = Lock()  # To ensure thread-safe access to open_ports

def scan_port(port, ip):
    """Scan a single port."""
    try:
        with socket.socket() as s:  # Ensure socket is closed after use
            s.settimeout(1)
            s.connect((ip, port))
            with lock:  # Ensure thread-safe access
                open_ports.append(port)
    except (ConnectionRefusedError, socket.timeout):
        pass

def prepare_threads(ports, ip):
    """Create and start threads for scanning ports."""
    thread_list = []
    for port in ports:
        thread = Thread(target=scan_port, args=(port, ip))
        thread_list.append(thread)
        thread.start()

    for t in thread_list:
        t.join()  # Wait for all threads to finish

def start_scan():
    """Start the port scan based on user input."""
    ip = ip_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    
    if not ip:
        messagebox.showerror("Input Error", "Please enter an IP address.")
        return
    
    ports = range(start_port, end_port + 1)
    open_ports.clear()  # Clear previous results
    result_text.delete(1.0, tk.END)  # Clear previous results display
    
    # Start scanning in a new thread
    scan_thread = Thread(target=lambda: run_scan(ports, ip))
    scan_thread.start()

def run_scan(ports, ip):
    """Run the scanning process and update the GUI."""
    prepare_threads(ports, ip)
    
    # Update results in the GUI
    result_text.insert(tk.END, f"Open Ports Found: {open_ports}\n")

# Set up the main application window
app = tk.Tk()
app.title("Port Scanner")

# Create input fields for IP address and port range
tk.Label(app, text="IP Address:").grid(row=0, column=0)
ip_entry = tk.Entry(app)
ip_entry.grid(row=0, column=1)

tk.Label(app, text="Start Port:").grid(row=1, column=0)
start_port_entry = tk.Entry(app)
start_port_entry.grid(row=1, column=1)

tk.Label(app, text="End Port:").grid(row=2, column=0)
end_port_entry = tk.Entry(app)
end_port_entry.grid(row=2, column=1)

# Create a button to start scanning
scan_button = tk.Button(app, text="Scan", command=start_scan)
scan_button.grid(row=3, columnspan=2)

# Create a scrolled text area to display results
result_text = scrolledtext.ScrolledText(app, width=40, height=10)
result_text.grid(row=4, columnspan=2)

# Start the GUI event loop
app.mainloop()