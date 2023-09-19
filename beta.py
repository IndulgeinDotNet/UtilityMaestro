import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
from scapy.all import *
import threading

# Define the correct access code
correct_access_code = "1234"

# Dictionary to store custom tools and their descriptions
custom_tools = {
    "Port Scanner": "Scan open ports on a target system.",
    "Vulnerability Scanner": "Scan for common vulnerabilities in a web application.",
    "Password Cracker": "Brute force or dictionary attack on password hashes.",
    "Network Sniffer": "Capture and analyze network traffic in a live, sortable way.",
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
    notebook = ttk.Notebook(app)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    for tool_name in custom_tools:
        tool_frame = ttk.Frame(notebook)
        notebook.add(tool_frame, text=tool_name)
        tool_frames[tool_name] = tool_frame  # Store the tool frames for future use

        if tool_name == "Port Scanner":
            create_tool(tool_frame, "Port Scanner", ["Target Host:", "Port Range (e.g., 80-100):"], port_scan)
        elif tool_name == "Vulnerability Scanner":
            create_tool(tool_frame, "Vulnerability Scanner", ["Target URL:"], vulnerability_scan)
        elif tool_name == "Password Cracker":
            create_tool(tool_frame, "Password Cracker", ["Target Password:", "Dictionary File:"], start_password_cracking)
        elif tool_name == "Network Sniffer":
            create_network_sniffer_tool(tool_frame)
        elif tool_name == "SQL Injection Tool":
            create_tool(tool_frame, "SQL Injection Tool", ["Target URL:", "SQL Payload:"], execute_sql_injection)
        else:
            create_info_label(tool_frame, custom_tools[tool_name])


def create_tool(tool_frame, tool_name, labels, command):
    tool_label = ttk.Label(tool_frame, text=tool_name, font=("Helvetica", 16))
    tool_label.pack(pady=10)

    for label_text in labels:
        label = ttk.Label(tool_frame, text=label_text)
        label.pack()

    entries = []
    for label_text in labels:
        entry = ttk.Entry(tool_frame)
        entry.pack()
        entries.append(entry)

    output_text = scrolledtext.ScrolledText(tool_frame, wrap=tk.WORD, width=40, height=10)
    output_text.pack(padx=10, pady=10)

    scan_button = ttk.Button(tool_frame, text="Start", command=lambda: command(*[entry.get() for entry in entries], output_text))
    scan_button.pack()


def create_network_sniffer_tool(tool_frame):
    tool_label = ttk.Label(tool_frame, text="Network Sniffer", font=("Helvetica", 16))
    tool_label.pack(pady=10)

    start_sniff_button = ttk.Button(tool_frame, text="Start Sniffing", command=lambda: start_network_sniffer(tool_frame))
    start_sniff_button.pack()

    stop_sniff_button = ttk.Button(tool_frame, text="Stop Sniffing", state=tk.DISABLED, command=lambda: stop_network_sniffer(tool_frame))
    stop_sniff_button.pack()

    save_checkbox_var = tk.IntVar()
    save_checkbox = ttk.Checkbutton(tool_frame, text="Save to File", variable=save_checkbox_var)
    save_checkbox.pack()

    output_text = scrolledtext.ScrolledText(tool_frame, wrap=tk.WORD, width=80, height=20)
    output_text.pack(padx=10, pady=10)

    tool_frame.network_sniffer_output_text = output_text
    tool_frame.network_sniffer_save_checkbox_var = save_checkbox_var
    tool_frame.network_sniffer_start_button = start_sniff_button
    tool_frame.network_sniffer_stop_button = stop_sniff_button


def start_network_sniffer(tool_frame):
    output_text = tool_frame.network_sniffer_output_text
    save_to_file = tool_frame.network_sniffer_save_checkbox_var.get()
    start_button = tool_frame.network_sniffer_start_button
    stop_button = tool_frame.network_sniffer_stop_button

    output_text.delete(1.0, tk.END)  # Clear any previous output

    def packet_capture(packet):
        packet_info = f"Packet: {packet.summary()}\n"

        if save_to_file:
            with open("sniffer_output.txt", "a") as file:
                file.write(packet_info)

        output_text.insert(tk.END, packet_info)
        output_text.see(tk.END)

    def sniff_thread():
        start_button.configure(state=tk.DISABLED)
        stop_button.configure(state=tk.NORMAL)
        sniff(prn=packet_capture, filter="ip")

    tool_frame.sniff_thread = threading.Thread(target=sniff_thread)
    tool_frame.sniff_thread.daemon = True
    tool_frame.sniff_thread.start()


def stop_network_sniffer(tool_frame):
    if hasattr(tool_frame, 'sniff_thread') and tool_frame.sniff_thread.is_alive():
        tool_frame.sniff_thread.join(timeout=1)
    tool_frame.network_sniffer_start_button.configure(state=tk.NORMAL)
    tool_frame.network_sniffer_stop_button.configure(state=tk.DISABLED)


sql_injection_payloads = [
    "' OR '1'='1'; -- ",
    "' OR 1=1; -- ",
    "' OR 'a'='a",
    "') OR ('a'='a",
    "'; WAITFOR DELAY '0:0:5' --",
    "' AND 1=CONVERT(INT, (SELECT @@version)); --",
]


def create_sql_injection_tool(tool_frame):
    tool_label = ttk.Label(tool_frame, text="SQL Injection Tool", font=("Helvetica", 16))
    tool_label.pack(pady=10)

    target_label = ttk.Label(tool_frame, text="Target URL:")
    target_label.pack()
    target_entry = ttk.Entry(tool_frame, width=50)
    target_entry.pack()

    payload_label = ttk.Label(tool_frame, text="SQL Payload:")
    payload_label.pack()
    payload_combo = ttk.Combobox(tool_frame, values=sql_injection_payloads, width=50)
    payload_combo.pack()

    result_label = ttk.Label(tool_frame, text="Result:")
    result_label.pack()
    result_text = scrolledtext.ScrolledText(tool_frame, wrap=tk.WORD, width=60, height=10)
    result_text.pack(padx=10, pady=10)

    scan_button = ttk.Button(tool_frame, text="Execute SQL Injection",
                             command=lambda: execute_sql_injection(target_entry.get(), payload_combo.get(), result_text))
    scan_button.pack()


def create_info_label(tool_frame, info_text):
    info_label = ttk.Label(tool_frame, text=info_text, wraplength=380)
    info_label.pack(padx=10, pady=10)


def port_scan(host, port_range, output_text):
    try:
        start_port, end_port = map(int, port_range.split('-'))

        output_text.delete(1.0, tk.END)  # Clear any previous output

        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((host, port))
            if result == 0:
                output_text.insert(tk.END, f"Port {port} is open\n")
            sock.close()

    except Exception as e:
        output_text.insert(tk.END, f"An error occurred: {str(e)}\n")


def vulnerability_scan(target_url, output_text):
    try:
        output_text.delete(1.0, tk.END)  # Clear any previous output
        response = requests.get(target_url)

        if response.status_code == 200:
            output_text.insert(tk.END, "Target web application is online.\n")
            # You can add vulnerability checks here based on the response content
        else:
            output_text.insert(tk.END, f"Failed to connect to the target URL. Status code: {response.status_code}\n")

    except Exception as e:
        output_text.insert(tk.END, f"An error occurred: {str(e)}\n")


def password_cracker(target_password, dictionary, output_text):
    # Implement password cracking functionality here
    pass


def start_password_cracking(target_password, dictionary_file, output_text):
    # Implement password cracking startup functionality here
    pass


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

info_label = ttk.Label(access_frame, text="This is a versatile utility suite. Please enter the access code to access the tools.")
info_label.pack(pady=10)

info_label = ttk.Label(access_frame, text="Created By IndulgeIn. Version 0.998- Zenklaeta", font=("Sans-serif", 7))
info_label.pack()

app.mainloop()
