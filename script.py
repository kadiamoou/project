import nmap

def scan_open_ports(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-p-")
    open_ports = []

    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            for port in scanner[host]['tcp']:
                if scanner[host]['tcp'][port]['state'] == 'open':
                    open_ports.append(port)

    return open_ports

def scan_services(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-p- -sV")
    services = []

    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            for port in scanner[host]['tcp']:
                if scanner[host]['tcp'][port]['state'] == 'open':
                    service_name = scanner[host]['tcp'][port]['name']
                    service_product = scanner[host]['tcp'][port]['product']
                    services.append({
                        'port': port,
                        'name': service_name,
                        'product': service_product
                    })

    return services

def main():
    target = input("Enter target IP address or hostname: ")
    print(f"Scanning open ports for target: {target}")

    open_ports = scan_open_ports(target)

    if open_ports:
        print("Open ports found:")
        for port in open_ports:
            print(f"Port: {port}")
    else:
        print("No open ports found.")

    print(f"\nScanning services for target: {target}")
    services = scan_services(target)

    if services:
        print("Services found:")
        for service in services:
            print(f"Port: {service['port']}, Name: {service['name']}, Product: {service['product']}")
    else:
        print("No services found.")

if name == "main":
    main()
