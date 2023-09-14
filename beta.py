import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import urllib.request
from scapy.all import *

# Define the correct access code
correct_access_code = "1234"

# Dictionary to store custom tools and their descriptions
custom_tools = {
    "Port Scanner": "Scan open ports on a target system.",
    "Vulnerability Scanner": "Scan for common vulnerabilities in a web application.",
    "Password Cracker": "Brute force or dictionary attack on password hashes.",
    "Network Sniffer": "Capture and analyze network traffic.",
    "SQL Injection Tool": "Test for SQL injection vulnerabilities in web applications."
}

# Dictionary to store tool windows
tool_windows = {}


def authenticate_access():
    entered_access_code = access_code_entry.get()
    if entered_access_code == correct_access_code:
        open_tools()
    else:
        messagebox.showerror("Access Code Error", "Incorrect access code")


def open_tools():
    access_frame.pack_forget()  # Hide the access frame

    # Create a frame for displaying tools
    tools_frame = ttk.Frame(app)
    tools_frame.pack(pady=20)

    # Create buttons for each tool
    for tool_name in custom_tools:
        tool_button = ttk.Button(tools_frame, text=tool_name, command=lambda name=tool_name: open_tool(name))
        tool_button.pack(fill=tk.BOTH, padx=10, pady=5)


def port_scan(host, port_range, output_text):
    try:
        start_port, end_port = map(int, port_range.split('-'))

        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Set a timeout for the connection attempt

            # Attempt to connect to the specified host and port
            result = sock.connect_ex((host, port))

            if result == 0:
                output_text.insert(tk.END, f"Port {port} is open\n")
            else:
                output_text.insert(tk.END, f"Port {port} is closed\n")

            sock.close()
    except Exception as e:
        output_text.insert(tk.END, f"Error scanning ports: {str(e)}\n")


def vulnerability_scan(target_url, output_text):
    try:
        # Send a GET request to the target URL using urllib
        response = urllib.request.urlopen(target_url)
        status_code = response.getcode()

        # Check if the response status code indicates a vulnerability
        if status_code == 200:
            output_text.insert(tk.END, f"Vulnerability found at {target_url}\n")
        else:
            output_text.insert(tk.END, f"No vulnerability found at {target_url}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error scanning {target_url}: {str(e)}\n")


def password_cracker(target_password, dictionary, output_text):
    found = False
    for guess in dictionary:
        if guess == target_password:
            output_text.insert(tk.END, f"Password cracked: {guess}\n")
            found = True
            break
    if not found:
        output_text.insert(tk.END, "Password not found in dictionary.\n")


def password_cracker_tool():
    password_cracker_window = tk.Toplevel(app)
    password_cracker_window.title("Password Cracker")
    password_cracker_window.geometry("400x400")

    password_cracker_label = ttk.Label(password_cracker_window, text="Password Cracker", font=("Helvetica", 16))
    password_cracker_label.pack(pady=10)

    password_label = ttk.Label(password_cracker_window, text="Target Password:")
    password_label.pack()
    password_entry = ttk.Entry(password_cracker_window)
    password_entry.pack()

    dictionary_label = ttk.Label(password_cracker_window, text="Dictionary File:")
    dictionary_label.pack()
    dictionary_entry = ttk.Entry(password_cracker_window)
    dictionary_entry.pack()

    output_text = scrolledtext.ScrolledText(password_cracker_window, wrap=tk.WORD, width=40, height=10)
    output_text.pack(padx=10, pady=10)

    crack_button = ttk.Button(password_cracker_window, text="Start Cracking",
                              command=lambda: start_password_cracking(password_entry.get(), dictionary_entry.get(),
                                                                      output_text))
    crack_button.pack()


def start_password_cracking(target_password, dictionary_file, output_text):
    try:
        with open(dictionary_file, "r") as file:
            dictionary = file.read().splitlines()
        password_cracker(target_password, dictionary, output_text)
    except Exception as e:
        output_text.insert(tk.END, f"Error cracking password: {str(e)}\n")


def network_sniffer(output_text):
    try:
        def packet_handler(packet):
            # Process and display the packet information
            output_text.insert(tk.END, f"Packet: {packet.summary()}\n")

        # Start sniffing packets on the default interface
        sniff(prn=packet_handler, count=10)  # Change count to the desired number of packets

    except Exception as e:
        output_text.insert(tk.END, f"Error sniffing packets: {str(e)}\n")


def open_tool(tool_name):
    info = custom_tools.get(tool_name, "Tool not found")
    tool_window = tk.Toplevel(app)
    tool_window.title(tool_name)
    tool_window.geometry("400x400")

    if tool_name == "Port Scanner":
        port_scanner_label = ttk.Label(tool_window, text="Port Scanner", font=("Helvetica", 16))
        port_scanner_label.pack(pady=10)

        host_label = ttk.Label(tool_window, text="Target Host:")
        host_label.pack()
        host_entry = ttk.Entry(tool_window)
        host_entry.pack()

        port_range_label = ttk.Label(tool_window, text="Port Range (e.g., 80-100):")
        port_range_label.pack()
        port_range_entry = ttk.Entry(tool_window)
        port_range_entry.pack()

        output_text = scrolledtext.ScrolledText(tool_window, wrap=tk.WORD, width=40, height=10)
        output_text.pack(padx=10, pady=10)

        scan_button = ttk.Button(tool_window, text="Start Scan",
                                 command=lambda: port_scan(host_entry.get(), port_range_entry.get(), output_text))
        scan_button.pack()
    elif tool_name == "Vulnerability Scanner":
        vulnerability_scanner_label = ttk.Label(tool_window, text="Vulnerability Scanner", font=("Helvetica", 16))
        vulnerability_scanner_label.pack(pady=10)

        target_label = ttk.Label(tool_window, text="Target URL:")
        target_label.pack()
        target_entry = ttk.Entry(tool_window)
        target_entry.pack()

        output_text = scrolledtext.ScrolledText(tool_window, wrap=tk.WORD, width=40, height=10)
        output_text.pack(padx=10, pady=10)

        scan_button = ttk.Button(tool_window, text="Start Scan",
                                 command=lambda: vulnerability_scan(target_entry.get(), output_text))
        scan_button.pack()
    elif tool_name == "Password Cracker":
        password_cracker_tool()
    elif tool_name == "Network Sniffer":
        network_sniffer(output_text)  # Call the network_sniffer function
    elif tool_name == "SQL Injection Tool":
        sql_injection_tool_tool()
    else:
        info_label = ttk.Label(tool_window, text=info, wraplength=380)
        info_label.pack(padx=10, pady=10)


def show_about():
    about_text = """
    UtilityMaestero\nVersion 2.0\n
    White-Hat Hacking and Penetration Testing Tool.
    Developed by indulgein
    """
    messagebox.showinfo("About UtilityMaestero", about_text)


app = tk.Tk()
app.title("UtilityMaestero")

# Calculate the center position of the window
screen_width = app.winfo_screenwidth()
screen_height = app.winfo_screenheight()
window_width = 400
window_height = 400
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2
app.geometry(f"{window_width}x{window_height}+{x}+{y}")

access_frame = ttk.Frame(app)
access_frame.pack()

access_label = ttk.Label(access_frame, text="Enter Access Code", font=("Helvetica", 20))
access_label.pack(pady=20)

access_code_label = ttk.Label(access_frame, text="Access Code:")
access_code_label.pack()

access_code_entry = ttk.Entry(access_frame, show="*")
access_code_entry.pack()

access_button = ttk.Button(access_frame, text="Access Tools", command=authenticate_access)
access_button.pack()

menu_bar = tk.Menu(app)
app.config(menu=menu_bar)

help_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="About UtilityMaestero", command=show_about)

app.mainloop()
