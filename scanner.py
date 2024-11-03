#gauravrokade2002
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import whois
import socket
import dns.resolver
import subprocess
from threading import Thread
import os

# Function to perform WHOIS lookup
def whois_lookup():
    domain = entry.get()
    try:
        w = whois.whois(domain)
        display_result(f"WHOIS Lookup for {domain}:\n{w}")
    except Exception as e:
        display_result(f"Error performing WHOIS lookup: {e}")

# Function to scan a single port
def scan_port(ip, port, result_box):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout of 1 second
        result = sock.connect_ex((ip, port))  # Attempts to connect
        if result == 0:
            result_box.insert(tk.END, f"Port {port} is open\n")
        sock.close()
    except Exception as e:
        result_box.insert(tk.END, f"Error scanning port {port}: {e}\n")

# Function to scan ports in the range 1-1024
def scan_ports(ip, result_box):
    for port in range(1, 1025):  # Scans ports from 1 to 1024
        scan_port(ip, port, result_box)

# Function to start port scanning in a separate thread
def start_port_scan(ip, result_box):
    result_box.delete(1.0, tk.END)  # Clear previous results
    result_box.insert(tk.END, "Scanning open ports...\n")
    scan_thread = Thread(target=scan_ports, args=(ip, result_box))
    scan_thread.start()

# Function to perform DNS Enumeration
def dns_enumeration():
    domain = entry.get()
    try:
        resolver = dns.resolver.Resolver()
        records = ['A', 'NS', 'MX', 'SOA', 'PTR', 'TXT']
        result = f"DNS Records for {domain}:\n"
        for record in records:
            try:
                answers = resolver.resolve(domain, record)
                for rdata in answers:
                    result += f"{record}: {rdata}\n"
            except Exception as e:
                result += f"{record} lookup failed: {e}\n"
        display_result(result)
    except Exception as e:
        display_result(f"Error performing DNS enumeration: {e}")

# Function to perform Traceroute
def traceroute():
    domain = entry.get()
    if not domain:
        display_result("Please enter a valid IP or domain for traceroute.\n")
        return
    try:
        # Use 'tracert' on Windows and 'traceroute' on Unix/Linux
        command = ['tracert', domain] if os.name == 'nt' else ['traceroute', domain]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            display_result(f"Traceroute for {domain}:\n{result.stdout}")
        else:
            display_result(f"Error performing traceroute: {result.stderr}")
    except Exception as e:
        display_result(f"Error performing traceroute: {e}")

# Function to display results in the output area
def display_result(text):
    output_area.delete(1.0, tk.END)
    output_area.insert(tk.INSERT, text)

# Function to save results to a text file
#gauravrokade2002
def save_results():
    file = filedialog.asksaveasfile(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file:
        file.write(output_area.get(1.0, tk.END))
        file.close()

# Create the main window
window = tk.Tk()
window.title("Network Tool")

# Create the input field
tk.Label(window, text="Enter IP or Domain:").pack()
entry = tk.Entry(window, width=50)
entry.pack()

# Create the tabs
tab_control = ttk.Notebook(window)

# Whois Tab
whois_tab = ttk.Frame(tab_control)
tab_control.add(whois_tab, text="WHOIS")
whois_button = tk.Button(whois_tab, text="Lookup", command=whois_lookup)
whois_button.pack()

# Port Scan Tab
port_scan_tab = ttk.Frame(tab_control)
tab_control.add(port_scan_tab, text="Port Scan")
port_scan_button = tk.Button(port_scan_tab, text="Scan", command=lambda: start_port_scan(entry.get(), output_area))
port_scan_button.pack()

# DNS Enumeration Tab
dns_tab = ttk.Frame(tab_control)
tab_control.add(dns_tab, text="DNS Enumeration")
dns_button = tk.Button(dns_tab, text="Enumerate", command=dns_enumeration)
dns_button.pack()

# Traceroute Tab
trace_tab = ttk.Frame(tab_control)
tab_control.add(trace_tab, text="Traceroute")
trace_button = tk.Button(trace_tab, text="Trace", command=traceroute)
trace_button.pack()

# Display the tab control
tab_control.pack(expand=1, fill="both")

# Create the output area
output_area = scrolledtext.ScrolledText(window, width=100, height=20)
output_area.pack()

# Create the save button
save_button = tk.Button(window, text="Save Results", command=save_results)
save_button.pack()

# Start the GUI event loop
window.mainloop()
#gauravrokade20002
