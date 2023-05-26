# project
https://youtu.be/ja_vgTzCCkU

Our script is written in Python programming language, it uses the nmap library to scan open ports and services on a target IP address or hostname. The script consists of several functions and a main entry point.The scan_open_ports(target) function performs a port scan on the specified target. It creates an instance of nmap.PortScanner() and uses it to scan all ports on the target. The open ports found during the scan are stored in a list called open_ports. The function then returns this list.
The scan_services(target) function is similar to scan_open_ports(), but it also includes service detection. It scans all ports on the target and gathers additional information about the services running on the open ports. The results are stored in a list of dictionaries called services, where each dictionary contains the port number, service name, and product. The function returns this list. The main() function is the entry point of the script. It prompts the user to enter a target IP address or hostname. The scan_open_ports() function is called to perform a port scan on the target, and the results are stored in the open_ports list. If open ports are found, they are displayed. Then, the scan_services() function is called to perform a service scan on the target, and the results are stored in the services list. If services are found, they are displayed.

At the end of the script, if name == "__main__": checks if the script is being run directly (as opposed to being imported as a module). If it is being run directly, the main() function is called to start the execution of the script.

When we run the script, it asks the user to enter the target IP address or hostname. It will then perform a port scan and display the open ports, if any. After that, it will perform a service scan and display information about the services running on the open ports, if any.
