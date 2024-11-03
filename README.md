# mytool
This repository contains a network tool application built using Python's Tkinter library. The tool provides functionalities for performing WHOIS lookups, port scanning, DNS enumeration, and traceroute operations. It is designed to assist network administrators and security professionals in analyzing network configurations and troubleshooting.
Features
WHOIS Lookup: Retrieve domain registration information.
Port Scanner: Scan a specified IP address for open ports.
DNS Enumeration: Fetch various DNS records for a domain.
Traceroute: Trace the path packets take to reach a specified destination.
Save Results: Save the output results to a text file.
Installation
To run this application, ensure you have Python 3.x installed on your machine. Then, follow these steps:

Install the required libraries: You may need to install the following libraries using pip:

bash
Copy code
pip install python-whois dnspython
Usage
Run the application: Execute the main script using Python:

bash
Copy code
python main.py
Interact with the GUI:

Enter an IP address or domain name in the input field.
Select the appropriate tab for the desired operation:
WHOIS: Click the "Lookup" button to perform a WHOIS lookup.
Port Scan: Click the "Scan" button to scan for open ports (1-1024).
DNS Enumeration: Click the "Enumerate" button to fetch DNS records.
Traceroute: Click the "Trace" button to perform a traceroute to the specified IP or domain.
The results will be displayed in the output area.
Click "Save Results" to save the output to a text file.
Screenshots
Add any relevant screenshots here to illustrate the application's interface and features.


Dependencies
This application requires the following Python libraries:

tkinter: For the GUI.
whois: For performing WHOIS lookups.
socket: For networking functionalities.
dns.resolver: For DNS queries.
subprocess: For executing system commands.
Acknowledgments
This project utilizes various libraries and resources. Special thanks to the developers of:

python-whois
dnspython
