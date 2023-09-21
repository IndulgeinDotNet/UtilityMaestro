import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import socket
import requests
import scapy.all
from scapy.sendrecv import sniff
from tkinter import IntVar, Checkbutton

from urllib3.util import parse_url

# Constants
CORRECT_ACCESS_CODE = "1234"

TOOL_DESCRIPTIONS = {
    "Port Scanner": "Scan open ports on a target system.",
    "Vulnerability Scanner": "Scan for common vulnerabilities in a web application.",
    "Password Cracker": "Brute force or dictionary attack on password hashes.",
    "Network Sniffer": "Capture and analyze network traffic in a live, sortable way.",
    "SQL Injection Tool": "Test for SQL injection vulnerabilities in web applications.",
}

sql_injection_payloads = [
    "' OR '1'='1'; -- ",
    "' OR 1=1; -- ",
    "' OR 'a'='a",
    "') OR ('a'='a",
    "'; WAITFOR DELAY '0:0:5' --",
    "' AND 1=CONVERT(INT, (SELECT @@version)); --",
]


# Function to create a tool frame
def create_tool_frame(tool_name, notebook):
    tool_frame = ttk.Frame(notebook)
    notebook.add(tool_frame, text=tool_name)
    return tool_frame


# Function to create a label
def create_label(parent, text, font=None, pady=0):
    label = ttk.Label(parent, text=text, font=font)
    label.pack(pady=pady)


# Function to create a scrolled text widget
def create_scrolled_text(parent, wrap, width, height, padx=0, pady=0):
    text_widget = scrolledtext.ScrolledText(parent, wrap=wrap, width=width, height=height)
    text_widget.pack(padx=padx, pady=pady)
    return text_widget


# Function to create an entry widget
def create_entry(parent, width):
    entry = ttk.Entry(parent, width=width)
    entry.pack()
    return entry


# Function to create a button
def create_button(parent, text, command):
    button = ttk.Button(parent, text=text, command=command)
    button.pack()
    return button


# Function to perform port scanning
def port_scan(host, port_range, output_text):
    try:
        start_port, end_port = map(int, port_range.split('-'))
        output_text.delete(1.0, tk.END)

        for port in range(start_port, end_port + 1):
            sock = scapy.all.socket.socket(scapy.all.socket.AF_INET, scapy.all.socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                output_text.insert(tk.END, f"Port {port} is open\n")
            sock.close()

    except Exception as e:
        output_text.insert(tk.END, f"An error occurred: {str(e)}\n")


# Function to perform vulnerability scanning
def vulnerability_scan(target_url, output_text):
    try:
        output_text.delete(1.0, tk.END)
        response = requests.get(target_url)

        if response.status_code == 200:
            output_text.insert(tk.END, "Target web application is online.\n")
        else:
            output_text.insert(tk.END, f"Failed to connect to the target URL. Status code: {response.status_code}\n")

    except Exception as e:
        output_text.insert(tk.END, f"An error occurred: {str(e)}\n")


# Function to perform password cracking
def password_cracker(target_password, dictionary, output_text):
    # Implement password cracking functionality here
    pass


# Function to start password cracking
def start_password_cracking(target_password, dictionary_file, output_text):
    # Implement password cracking startup functionality here
    pass


# Function to execute SQL injection testing
def execute_sql_injection(target_url, sql_payload, output_text):
    try:
        response = requests.get(target_url + "?param=" + sql_payload)

        if "error" in response.text.lower():
            output_text.insert(tk.END, "SQL Injection Detected!\n")
        else:
            output_text.insert(tk.END, "No SQL Injection Detected.\n")

        output_text.insert(tk.END, "Response Content:\n")
        output_text.insert(tk.END, response.text)

    except Exception as e:
        output_text.insert(tk.END, f"An error occurred: {str(e)}\n")


# Function to create the Port Scanner tool
def create_port_scanner_tool(tool_frame):
    create_label(tool_frame, "Port Scanner", font=("Helvetica", 16), pady=10)
    host_label = create_label(tool_frame, "Target Host:")
    host_entry = create_entry(tool_frame, 40)
    port_range_label = create_label(tool_frame, "Port Range (e.g., 80-100):")
    port_range_entry = create_entry(tool_frame, 40)
    output_text = create_scrolled_text(tool_frame, tk.WORD, 40, 10, padx=10, pady=10)

    create_button(tool_frame, "Start Scan", lambda: port_scan(host_entry.get(), port_range_entry.get(), output_text))


# Function to create the Vulnerability Scanner tool
def create_vulnerability_scanner_tool(tool_frame):
    create_label(tool_frame, "Vulnerability Scanner", font=("Helvetica", 16), pady=10)
    target_label = create_label(tool_frame, "Target URL:")
    target_entry = create_entry(tool_frame, 40)
    output_text = create_scrolled_text(tool_frame, tk.WORD, 40, 10, padx=10, pady=10)

    create_button(tool_frame, "Start Scan", lambda: vulnerability_scan(target_entry.get(), output_text))


# Function to create the Password Cracker tool
def create_password_cracker_tool(tool_frame):
    create_label(tool_frame, "Password Cracker", font=("Helvetica", 16), pady=10)
    password_label = create_label(tool_frame, "Target Password:")
    password_entry = create_entry(tool_frame, 50)
    dictionary_label = create_label(tool_frame, "Dictionary File:")
    dictionary_entry = create_entry(tool_frame, 50)
    result_label = create_label(tool_frame, "Result:")
    result_text = create_scrolled_text(tool_frame, tk.WORD, 60, 10, padx=10, pady=10)

    create_button(tool_frame, "Start Cracking",
                  lambda: start_password_cracking(password_entry.get(), dictionary_entry.get(), result_text))



def create_network_sniffer_tool(tool_frame):
    create_label(tool_frame, "Network Sniffer", font=("Helvetica", 16), pady=10)

    output_text = create_scrolled_text(tool_frame, tk.WORD, 80, 20, padx=10, pady=10)
    packet_list = []

    def packet_capture(packet):
        packet_info = f"Packet: {packet.summary()}\n"
        packet_list.append(packet_info)
        output_text.insert(tk.END, packet_info)
        output_text.see(tk.END)

    def start_sniffing():
        nonlocal packet_list
        packet_list = []  # Clear the packet list
        output_text.delete(1.0, tk.END)  # Clear the output text
        save_to_file = save_checkbox_var.get()

        def sniff_thread():
            sniff(prn=packet_capture, store=False)

        if hasattr(tool_frame, 'sniff_thread') and tool_frame.sniff_thread.is_alive():
            return

        tool_frame.sniff_thread = threading.Thread(target=sniff_thread, daemon=True)
        tool_frame.sniff_thread.start()

        # Disable the start button after starting
        start_button.configure(state=tk.DISABLED)
        # Enable the stop button
        stop_button.configure(state=tk.NORMAL)

    def stop_sniffing():
        if hasattr(tool_frame, 'sniff_thread') and tool_frame.sniff_thread.is_alive():
            tool_frame.sniff_thread.join(timeout=1)

        # Enable the start button after stopping
        start_button.configure(state=tk.NORMAL)
        # Disable the stop button
        stop_button.configure(state=tk.DISABLED)

    start_button = create_button(tool_frame, "Start Sniffing", start_sniffing)
    stop_button = create_button(tool_frame, "Stop Sniffing", stop_sniffing)
    stop_button.configure(state=tk.DISABLED)

    save_checkbox_var = IntVar()
    save_checkbox = Checkbutton(tool_frame, text="Save to File", variable=save_checkbox_var)
    save_checkbox.pack()


# Function to authenticate access
def authenticate_access():
    entered_access_code = access_code_entry.get()
    if entered_access_code == CORRECT_ACCESS_CODE:
        open_tools()
    else:
        messagebox.showerror("Access Code Error", "Incorrect access code")


# Function to open the toolset
def open_tools():
    access_frame.pack_forget()
    notebook = ttk.Notebook(app)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    for tool_name, tool_description in TOOL_DESCRIPTIONS.items():
        tool_frame = create_tool_frame(tool_name, notebook)
        create_info_label(tool_frame, tool_description)
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


# Function to create an information label
def create_info_label(tool_frame, info_text):
    info_label = ttk.Label(tool_frame, text=info_text, wraplength=380)
    info_label.pack(padx=10, pady=10)


# Function to create the SQL Injection Tool
def create_sql_injection_tool(tool_frame):
    create_label(tool_frame, "SQL Injection Tool", font=("Helvetica", 16), pady=10)
    target_label = create_label(tool_frame, "Target URL:")
    target_entry = create_entry(tool_frame, 50)
    payload_label = create_label(tool_frame, "SQL Payload:")
    payload_combo = ttk.Combobox(tool_frame, values=sql_injection_payloads, width=50)
    payload_combo.pack()
    result_label = create_label(tool_frame, "Result:")
    result_text = create_scrolled_text(tool_frame, tk.WORD, 60, 10, padx=10, pady=10)

    create_button(tool_frame, "Execute SQL Injection",
                  lambda: execute_sql_injection(target_entry.get(), payload_combo.get(), result_text))


# Main application setup
app = tk.Tk()
app.title("UtilityMaestro")

screen_width = app.winfo_screenwidth()
screen_height = app.winfo_screenheight()
window_width = 800
window_height = 600
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2
app.geometry(f"{window_width}x{window_height}+{x}+{y}")

access_frame = ttk.Frame(app)
access_frame.pack(fill=tk.BOTH, expand=True)

access_label = ttk.Label(access_frame, text="Welcome to UtilityMaestro", font=("Helvetica", 20))
access_label.pack(pady=20)

access_code_label = ttk.Label(access_frame, text="Enter Access Code:")
access_code_label.pack()

access_code_entry = ttk.Entry(access_frame, show="*")
access_code_entry.pack()

access_button = ttk.Button(access_frame, text="Access Tools", command=authenticate_access)
access_button.pack()

info_label = ttk.Label(access_frame,
                       text="This is a versatile utility suite. Please enter the access code to access the tools.")
info_label.pack(pady=10)

info_label = ttk.Label(access_frame, text="Created By IndulgeIn. Version 0.998- Zenklaeta", font=("Sans-serif", 7))
info_label.pack()

app.mainloop()
