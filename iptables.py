import subprocess

def is_ip_blocked(ip_address):
    # Execute the iptables command to list current rules
    command = "sudo iptables -L INPUT -n"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    # Check if the IP address is present in the output
    return ip_address in result.stdout

def drop_packet(source_ip):
    if not is_ip_blocked(source_ip):
        command = f"sudo iptables -A INPUT  -s {source_ip} -j DROP"
    #c2 = f"sudo ufw reload"
    #ommand = f"echo sudo iptables -A INPUT -s {source_ip} -d {destination_ip} -j DROP"
        subprocess.run(command, shell=True)
    #subprocess.run(c2, shell=True)
