from scapy.all import sniff
import protocol_mapping
import subprocess

def drop_packet(source_ip, destination_ip):
    command = f"sudo iptables -A INPUT -s {source_ip} -d {destination_ip} -j DROP"
    subprocess.run(command, shell=True)

def match_snort_rule(packet_info, rule):
    rule_parts = rule.split()

    if len(rule_parts) >= 4 and rule_parts[0] == "alert":
        # Extract details from the Snort rule
        rule_proto = rule_parts[1]
        rule_src_ip = rule_parts[2]
        rule_src_port = rule_parts[3]
        rule_dst_ip = rule_parts[5]
        rule_dst_port = rule_parts[6]
        #print(rule_proto, " - ", packet_info["protocol"])
        # Check if the packet matches the rule
        #print(protocol_mapping[packet_info["protocol"]], ' - ', packet_info["src_ip"])
        if (protocol_mapping.protocol_mapping[packet_info["protocol"]] == rule_proto and (rule_src_ip == 'any' or rule_src_ip == packet_info["src_ip"]) and (rule_src_port == 'any' or rule_src_port == packet_info["src_port"]) and (rule_dst_ip == 'any' or rule_dst_ip == packet_info["dst_ip"]) and (rule_dst_port == 'any' or rule_dst_port == packet_info["dst_port"])):
            if(rule_parts[0] == 'drop'):
                drop_packet(packet_info['src_ip'], packet_info['dst_ip'])
            start_index = rule.find('"')  # Find the first occurrence of 'a'
            end_index = rule.find('"', start_index + 1)  # Find the next 'a' after the start index

            if start_index != -1 and end_index != -1:  # If both 'a's are found
                substring = rule[start_index + 1:end_index]
                print(substring)


def match_rules(packet_info):
    with open('rules.txt', 'r') as file:
    # Read the file line by line
        for line in file:
            str = line.strip()+" "
            if(str[0] != ' ' and str[0] != '#'):
                rule = str
                match_snort_rule(packet_info, rule)


# ... (rest of the code remains unchanged)


# Function to process packets
def process_packet(packet):
    # Extract all packet information
    ip_layer = packet.getlayer("IP")
    tcp_layer = packet.getlayer("TCP")
    udp_layer = packet.getlayer("UDP")
    icmp_layer = packet.getlayer("ICMP")  # Extract ICMP layer
    
    packet_info = {
        "src_ip": ip_layer.src if ip_layer else None,
        "dst_ip": ip_layer.dst if ip_layer else None,
        "src_port": tcp_layer.sport if tcp_layer else (udp_layer.sport if udp_layer else None),
        "dst_port": tcp_layer.dport if tcp_layer else (udp_layer.dport if udp_layer else None),
        "protocol": ip_layer.proto if ip_layer else None,
        "ttl": ip_layer.ttl if ip_layer else None,
        "flags": tcp_layer.flags if tcp_layer else None,
        "payload": str(packet.payload) if hasattr(packet, "payload") else None,
        "icmp_type": icmp_layer.type if icmp_layer else None,
        "icmp_code": icmp_layer.code if icmp_layer else None,
    }

    # Pass the packet information to the custom rule matching function
    match_rules(packet_info)


# Start capturing packets on eth0 and process each packet
def start_sniffing():
    sniff(iface='ens33', prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffing()


'''# Function to match packets against custom rules
def match_rules(packet_info):
    # Your custom rule matching logic goes here
    # For example:
    print(packet_info["protocol"])
    if packet_info["protocol"] == 6:
        print("Detected HTTP traffic to port 80")
    #elif packet_info["protocol"] == "UDP" and packet_info["src_port"] == 53:
        #print("Detected DNS traffic from port 53")
    # Add more rules as needed
    '''
    
