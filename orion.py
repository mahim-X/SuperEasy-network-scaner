import socket
import subprocess
from tqdm import tqdm
import time

def display_banner():
    banner = """
    ##############################################################
    #                                                            #
    #           orion pax Network Scanner by mahimX              #
    #                                                            #
    ##############################################################
    """
    print(banner)

def get_dns_info(domain):
    try:
        print(f"\n[+] Fetching DNS Information for {domain}...\n")
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
        print(f"A Record: {socket.gethostbyname_ex(domain)}")
    except socket.gaierror:
        print("[-] Failed to resolve DNS. Check the domain name.")

def scan_ports_with_progress(ip, ports=None, syn_scan=False):
    print(f"\n[+] Scanning Open Ports with Service Versions on {ip}...\n")

    try:
        
        total_ports = len(ports) if ports else 65535
        with tqdm(total=total_ports, desc="Scanning Ports", unit="port") as progress:
            
            if ports:
                port_range = ",".join(map(str, ports))
                if syn_scan:
                    command = ["nmap", "-sS", "-p", port_range, ip]  
                else:
                    command = ["nmap", "-sV", "-p", port_range, ip]  
            else:
                command = ["nmap", "-sV", ip]

            
            result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            
            for i in range(total_ports):
                time.sleep(0.2)  
                progress.update(1)
            
            
            output, error = result.communicate()
            progress.close()

            if result.returncode == 0:
                
                output_str = output.decode()
                filtered_output = ""
                
                
                for line in output_str.splitlines():
                    if not any(substring in line for substring in ["Service detection performed", "Nmap done"]):
                        filtered_output += line + "\n"
                
                print("\n" + filtered_output)
            else:
                print("\n[-] Error occurred during scanning.")
                print(error.decode())
    except Exception as e:
        print(f"[-] Exception during scan: {e}")

def scan_top_ports(ip):
    
    top_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 
        8080, 8443, 3306, 1723, 5900, 993, 995
    ]
    scan_ports_with_progress(ip, top_ports)

def scan_specified_range(ip, start_port, end_port):
    port_range = list(range(start_port, end_port + 1))
    scan_ports_with_progress(ip, port_range, syn_scan=True)  

def main():
    display_banner()  

    while True:
        print("\n=== Network Scanning Tool ===")
        print("1. DNS Information Retrieval")
        print("2. Discover Open Ports")
        print("3. Exit")
        
        choice = input("\nSelect an option (1/2/3): ").strip()
        
        if choice == '1':
            domain = input("\nEnter the domain name (e.g., example.com): ").strip()
            get_dns_info(domain)
        elif choice == '2':
            ip = input("\nEnter the target IP address: ").strip()
            print("\n=== Open Port Scanning Options ===")
            print("1. Basic Scan (Top 20 Common Ports)")
            print("2. Scan Specified Range")
            
            scan_choice = input("\nSelect an option (1/2): ").strip()
            if scan_choice == '1':
                scan_top_ports(ip)
            elif scan_choice == '2':
                try:
                    start_port = int(input("\nEnter the starting port: ").strip())
                    end_port = int(input("Enter the ending port: ").strip())
                    if 0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port:
                        scan_specified_range(ip, start_port, end_port)
                    else:
                        print("[-] Invalid port range. Ports must be between 0 and 65535.")
                except ValueError:
                    print("[-] Invalid input. Please enter valid numbers for ports.")
            else:
                print("\nInvalid option. Returning to main menu.")
        elif choice == '3':
            print("\nExiting the tool. Goodbye!")
            break
        else:
            print("\nInvalid option. Please try again.")

if __name__ == "__main__":
    main()
    
    
    
    
  
