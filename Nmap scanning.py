import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import nmap
import threading
import socket

def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

def fill_local_ip():
    ip_entry.delete(0, tk.END)
    ip_entry.insert(0, get_local_ip())

def scan_ports(ip, port_range, scan_type, progress_var):
    open_ports = []

    nm = nmap.PortScanner()

    try:
        if not port_range:  # If no port range provided, scan all ports
            port_range = "1-65535"

        if scan_type == "TCP SYN":
            nm.scan(ip, arguments=f"-p {port_range} -sS -T4")
        elif scan_type == "UDP":
            nm.scan(ip, arguments=f"-p U:{port_range} -sU -Pn -T4")
        elif scan_type == "Comprehensive":
            nm.scan(ip, arguments=f"-p {port_range} -v -sS -sV -sC -A -O -T4")
        else:
            messagebox.showerror("Error", "Unsupported scan type selected.")
            return open_ports

        open_ports = get_nmap_open_ports(nm)
    except Exception as e:
        print(e)
        pass

    progress_var.set(100)  # Set progress to 100% after completion
    return open_ports

def get_nmap_open_ports(nm):
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_state = nm[host][proto][port]['state']
                port_service = nm[host][proto][port].get('product', 'Unknown')
                port_info = f"Port {port}/{proto} is {port_state} on {host}: {port_service}"
                
                # Include OS information
                os_info = nm[host].get('osclass', [])
                if os_info:
                    os_info_str = ', '.join([f"{item['osfamily']} {item['osgen']}" for item in os_info])
                    port_info += f", OS: {os_info_str}"
                
                open_ports.append(port_info)
    return open_ports

def start_scan(progress_var):
    ip = ip_entry.get()
    port_range = port_range_entry.get()
    scan_type = scan_var.get()

    if not ip:
        messagebox.showerror("Error", "Please enter an IP address.")
        return

    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)

    progress_var.set(0)  # Reset progress to 0%
    
    def scan_thread():
        for i in range(100):
            # Simulate scanning progress
            window.after(50, progress_var.set, i)
            window.update_idletasks()

        open_ports = scan_ports(ip, port_range, scan_type, progress_var)

        if open_ports:
            for port_info in open_ports:
                window.after(0, lambda: result_text.insert(tk.END, port_info + "\n"))
        else:
            window.after(0, lambda: result_text.insert(tk.END, "No open ports found."))
        
        window.after(0, lambda: result_text.config(state=tk.DISABLED))

    scan_thread = threading.Thread(target=scan_thread)
    scan_thread.start()

window = tk.Tk()
window.title("Port Scanner")

ip_label = tk.Label(window, text="Enter IP Address:")
ip_label.pack()
ip_entry = tk.Entry(window)
ip_entry.pack()

# Button to get local IP
get_ip_button = tk.Button(window, text="Get My IP Address", command=fill_local_ip)
get_ip_button.pack()

port_range_label = tk.Label(window, text="Enter Port Range (e.g., 80-100):")
port_range_label.pack()
port_range_entry = tk.Entry(window)
port_range_entry.pack()

scan_var = tk.StringVar(value="TCP SYN")  # Default to TCP SYN
scan_label = tk.Label(window, text="Select Scan Type:")
scan_label.pack()
scan_menu = tk.OptionMenu(window, scan_var, "TCP SYN", "UDP","Comprehensive")
scan_menu.pack()

scan_button = tk.Button(window, text="Scan Ports", command=lambda: start_scan(progress_var))
scan_button.pack()

result_text = tk.Text(window, height=10, width=60, state=tk.DISABLED)
result_text.pack()
# Scanning Label
scanning_label = tk.Label(window, text="Scanning Progress:")
scanning_label.pack()

# Progress Bar
progress_var = tk.DoubleVar()
progress_bar = tk.ttk.Progressbar(window, mode='determinate', length=200, variable=progress_var)
progress_bar.pack()

window.mainloop()
