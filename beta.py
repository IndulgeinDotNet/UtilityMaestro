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

# Dictionary to store tool frames
tool_frames = {}


def authenticate_access():
    entered_access_code = access_code_entry.get()
    if entered_access_code == correct_access_code:
        open_tools()
    else:
        messagebox.showerror("Access Code Error", "Incorrect access code")


def open_tools():
    access_frame.pack_forget()  # Hide the access frame

    # Create a notebook (tabbed interface) for tools
    notebook = ttk.Notebook(app)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Create frames for each tool and add them as tabs
    for tool_name in custom_tools:
        tool_frame = ttk.Frame(notebook)
        notebook.add(tool_frame, text=tool_name)
        tool_frames[tool_name] = tool_frame  # Store the tool frames for future use

        if tool_name == "Port Scanner":
            create_port_scanner_tool(tool_frame)
        elif tool_name == "Vulnerability Scanner":
            create_vulnerability_scanner_tool(tool_frame)
        elif tool_name == "Password Cracker":
            create_password_cracker_tool(tool_frame)
        elif tool_name == "Network Sniffer":
            create_network_sniffer_tool(tool_frame)
        elif tool_name == "SQL Injection Tool":
            create_sql_injection_tool(tool_frame)
        else:
            create_info_label(tool_frame, custom_tools[tool_name])


def create_port_scanner_tool(tool_frame):
    tool_label = ttk.Label(tool_frame, text="Port Scanner", font=("Helvetica", 16))
    tool_label.pack(pady=10)

    host_label = ttk.Label(tool_frame, text="Target Host:")
    host_label.pack()
    host_entry = ttk.Entry(tool_frame)
    host_entry.pack()

    port_range_label = ttk.Label(tool_frame, text="Port Range (e.g., 80-100):")
    port_range_label.pack()
    port_range_entry = ttk.Entry(tool_frame)
    port_range_entry.pack()

    output_text = scrolledtext.ScrolledText(tool_frame, wrap=tk.WORD, width=40, height=10)
    output_text.pack(padx=10, pady=10)

    scan_button = ttk.Button(tool_frame, text="Start Scan",
                             command=lambda: port_scan(host_entry.get(), port_range_entry.get(), output_text))
    scan_button.pack()


def create_vulnerability_scanner_tool(tool_frame):
    tool_label = ttk.Label(tool_frame, text="Vulnerability Scanner", font=("Helvetica", 16))
    tool_label.pack(pady=10)

    target_label = ttk.Label(tool_frame, text="Target URL:")
    target_label.pack()
    target_entry = ttk.Entry(tool_frame)
    target_entry.pack()

    output_text = scrolledtext.ScrolledText(tool_frame, wrap=tk.WORD, width=40, height=10)
    output_text.pack(padx=10, pady=10)

    scan_button = ttk.Button(tool_frame, text="Start Scan",
                             command=lambda: vulnerability_scan(target_entry.get(), output_text))
    scan_button.pack()


def create_password_cracker_tool(tool_frame):
    tool_label = ttk.Label(tool_frame, text="Password Cracker", font=("Helvetica", 16))
    tool_label.pack(pady=10)

    password_label = ttk.Label(tool_frame, text="Target Password:")
    password_label.pack()
    password_entry = ttk.Entry(tool_frame)
    password_entry.pack()

    dictionary_label = ttk.Label(tool_frame, text="Dictionary File:")
    dictionary_label.pack()
    dictionary_entry = ttk.Entry(tool_frame)
    dictionary_entry.pack()

    output_text = scrolledtext.ScrolledText(tool_frame, wrap=tk.WORD, width=40, height=10)
    output_text.pack(padx=10, pady=10)

    crack_button = ttk.Button(tool_frame, text="Start Cracking",
                              command=lambda: start_password_cracking(password_entry.get(), dictionary_entry.get(),
                                                                      output_text))
    crack_button.pack()


def create_network_sniffer_tool(tool_frame):
    tool_label = ttk.Label(tool_frame, text="Network Sniffer", font=("Helvetica", 16))
    tool_label.pack(pady=10)

    output_text = scrolledtext.ScrolledText(tool_frame, wrap=tk.WORD, width=40, height=10)
    output_text.pack(padx=10, pady=10)

    sniff_button = ttk.Button(tool_frame, text="Start Sniffing",
                              command=lambda: network_sniffer(output_text))
    sniff_button.pack()


def create_sql_injection_tool(tool_frame):
    tool_label = ttk.Label(tool_frame, text="SQL Injection Tool", font=("Helvetica", 16))
    tool_label.pack(pady=10)

    # Implement SQL Injection Tool UI components and functionality here


def create_info_label(tool_frame, info_text):
    info_label = ttk.Label(tool_frame, text=info_text, wraplength=380)
    info_label.pack(padx=10, pady=10)


def port_scan(host, port_range, output_text):
    # Implement port scanning functionality here
    pass


def vulnerability_scan(target_url, output_text):
    # Implement vulnerability scanning functionality here
    pass


def password_cracker(target_password, dictionary, output_text):
    # Implement password cracking functionality here
    pass


def start_password_cracking(target_password, dictionary_file, output_text):
    # Implement password cracking startup functionality here
    pass


def network_sniffer(output_text):
    # Implement network sniffing functionality here
    pass


app = tk.Tk()
app.title("UtilityMaestero")

# Calculate the center position of the window
screen_width = app.winfo_screenwidth()
screen_height = app.winfo_screenheight()
window_width = 800
window_height = 600
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2
app.geometry(f"{window_width}x{window_height}+{x}+{y}")

access_frame = ttk.Frame(app)
access_frame.pack(fill=tk.BOTH, expand=True)

access_label = ttk.Label(access_frame, text="Enter Access Code", font=("Helvetica", 20))
access_label.pack(pady=20)

access_code_label = ttk.Label(access_frame, text="Access Code:")
access_code_label.pack()

access_code_entry = ttk.Entry(access_frame, show="*")
access_code_entry.pack()

access_button = ttk.Button(access_frame, text="Access Tools", command=authenticate_access)
access_button.pack()

app.mainloop()
