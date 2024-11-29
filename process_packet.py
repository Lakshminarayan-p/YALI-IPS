import csv
import os
import re
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers import http
from iptables import drop_packet, is_ip_blocked
import protocol_mapping

# Global Variables
n = 1
source_ip_packet_counts = defaultdict(lambda: deque(maxlen=1000))
rules_by_protocol = defaultdict(list)
fragments = {}  # Store fragmented packets


def parse_snort_rule(rule):
    # Parsing the rule once when loaded
    rule_parts = re.split(r'[:)\s"]', rule)
    if len(rule_parts) >= 4 and rule_parts[0] in ["alert", "drop"]:
        msg_start_index = rule.find('msg: "') + 6  # Finds the start of the msg content
        msg_end_index = rule.find('"', msg_start_index)  # Finds the end of the msg content
        msg_content = rule[msg_start_index:msg_end_index] if msg_start_index > 5 and msg_end_index != -1 else "No message specified"
        return {
            'action': rule_parts[0],
            'proto': rule_parts[1],
            'src_ip': rule_parts[2],
            'src_port': rule_parts[3],
            'dst_ip': rule_parts[5],
            'dst_port': rule_parts[6],
            'flag': rule[rule.find('flags') + 7] if 'flags' in rule else None,
            'content': rule[rule.find('content') + 10:rule.find('"', rule.find('content') + 10)] if 'content' in rule else None,
            'threshold': re.search(r'threshold:.*?count (\d+), seconds (\d+)', rule),
            'sid': rule[rule.find("sid:") + 4:rule.find(';', rule.find('sid:'))].strip(')'),
            'msg': msg_content,
            'id': rule
        }
    return None


def load_rules():
    global rules_by_protocol
    rules_by_protocol = defaultdict(list)

    with open('rules.txt', 'r') as file:
        for line in file:
            rule = line.strip()
            if rule and not rule.startswith('#'):
                parsed_rule = parse_snort_rule(rule)
                if parsed_rule:
                    # Group rules by protocol, including 'any'
                    rules_by_protocol[parsed_rule['proto']].append(parsed_rule)


def check_and_block_packets(source_ip, time_window_seconds, max_packet_count):
    current_time = datetime.now()
    packet_times = source_ip_packet_counts[source_ip]
    
    # Remove expired entries from the deque
    while packet_times and (current_time - packet_times[0] > timedelta(seconds=time_window_seconds)):
        packet_times.popleft()

    # Add the current packet time to the list
    source_ip_packet_counts[source_ip].append(current_time)
    
    if len(source_ip_packet_counts[source_ip]) > max_packet_count:
        print("Potential DoS attack detected from", source_ip, "within", time_window_seconds, "seconds. Dropping packets.")
        return 1


def match_snort_rule(packet_info, rule):
    if ((protocol_mapping.protocol_mapping[packet_info["protocol"]] == rule['proto'] or rule['proto'] == 'any') and 
        (rule['src_ip'] == 'any' or rule['src_ip'] == packet_info["src_ip"]) and 
        (rule['src_port'] == 'any' or rule['src_port'] == packet_info["src_port"]) and 
        (rule['dst_ip'] == 'any' or rule['dst_ip'] == packet_info["dst_ip"]) and 
        (rule['dst_port'] == 'any' or rule['dst_port'] == packet_info["dst_port"]) and 
        (rule['flag'] == None or rule['flag'] == packet_info['flags']) and 
        (rule['content'] == None or (rule['content'] in packet_info["payload"]) or (rule['content'] in packet_info["url"]))):
        
        threshold_match = rule['threshold']
        if threshold_match:
            count = int(threshold_match.group(1))
            seconds = int(threshold_match.group(2))
            rule_threshold_flag = check_and_block_packets(rule['id'], time_window_seconds=seconds, max_packet_count=count)
            if rule_threshold_flag != 1:
                return
        
        if rule['action'] == 'drop':
            print("droping packet from", packet_info['src_ip'])
            drop_packet(packet_info['src_ip'])

        file_path = 'alerts_log.csv'
        with open(file_path, 'r') as file:
            line_count = sum(1 for line in file)
        
        with open(file_path, mode='a', newline='') as file:
            rule_sid = rule['sid']
            current_time = datetime.now()
            log = [[line_count, current_time, rule['action'], rule['msg'], rule_sid]]
            writer = csv.writer(file)
            writer.writerows(log)
        
        if rule['action'] == 'drop':
            return 1


def match_rules(packet_info):
    global n
    n += 1
    print(protocol_mapping.protocol_mapping[packet_info["protocol"]], "packet detected from", packet_info["src_ip"], 'to port:', packet_info['dst_port'], 
          "Flag:", packet_info['flags'], "\nwith payload:", packet_info['payload'])
    print("----------------")
    
    proto_rules = rules_by_protocol.get(protocol_mapping.protocol_mapping[packet_info["protocol"]], [])
    any_proto_rules = rules_by_protocol.get('any', [])
    relevant_rules = proto_rules + any_proto_rules

    for rule in relevant_rules:
        if match_snort_rule(packet_info, rule) == 1:
            return 1


def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()


# Reassemble fragmented IP packets
def reassemble_fragments(fragments):
    fragments.sort(key=lambda x: x[IP].frag)
    data = b""
    for fragment in fragments:
        if fragment.haslayer(Raw):
            data += bytes(fragment[Raw].load)
    reassembled_packet = fragments[0].copy()
    reassembled_packet[Raw].load = data
    del reassembled_packet[IP].chksum
    return reassembled_packet


# Detect malicious content
def is_malicious(packet):
    malicious_signature = b'BADCONTENT'
    payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
    return malicious_signature in payload


# Report and block malicious IP
def report_malicious(packet):
    src_ip = packet[IP].src
    block_ip(src_ip)


# Block IP function
def block_ip(ip_address):
    try:
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
        print(f"Successfully blocked {ip_address}.")
    except Exception as e:
        print(f"Error blocking IP address: {e}")


def process_packet(packet):
    packet = IP(packet.get_payload())
    
    if packet.haslayer(IP) and (packet[IP].flags & 1 or packet[IP].frag > 0):
        key = (packet[IP].src, packet[IP].dst, packet[IP].id)
        if key not in fragments:
            fragments[key] = []
        fragments[key].append(packet)
        if not packet[IP].flags & 1:
            reassembled_packet = reassemble_fragments(fragments[key])
            if is_malicious(reassembled_packet):
                report_malicious(reassembled_packet)
            del fragments[key]
    else:
        ip_layer = packet.getlayer("IP")
        tcp_layer = packet.getlayer("TCP")
        udp_layer = packet.getlayer("UDP")
        icmp_layer = packet.getlayer("ICMP")
        http_layer = packet.getlayer(http.HTTPRequest)

        payload = ''
        if TCP in packet and packet.haslayer(Raw):
            payload = packet[Raw].load.decode("utf-8", errors="ignore")

        url = ''
        if http_layer:
            url = get_url(packet)
            print("[+] HTTPRequest >", url)

        packet_info = {
            "src_ip": ip_layer.src if ip_layer else None,
            "dst_ip": ip_layer.dst if ip_layer else None,
            "src_port": tcp_layer.sport if tcp_layer else (udp_layer.sport if udp_layer else None),
            "dst_port": str(tcp_layer.dport) if tcp_layer else (udp_layer.dport if udp_layer else None),
            "protocol": ip_layer.proto if ip_layer else None,
            "ttl": ip_layer.ttl if ip_layer else None,
            "flags": tcp_layer.flags if tcp_layer else None,
            "payload": payload,
            "icmp_type": icmp_layer.type if icmp_layer else None,
            "icmp_code": icmp_layer.code if icmp_layer else None,
            "time": packet.time,
            "url": url,
        }

        if packet_info["src_ip"] and not is_ip_blocked(packet_info["src_ip"]):
            if match_rules(packet_info) == 1:
                return 1
        
        return 0


def start_nfqueue(queue_num=1):
    load_rules()
    print("Loaded rules, starting NetfilterQueue")

    subprocess.call(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', str(queue_num)])
    subprocess.call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', str(queue_num)])
    
    def nfqueue_handler(packet):
        result = process_packet(packet)
        if result == 1:
            packet.drop()
        else:
            packet.accept()
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, nfqueue_handler)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Stopping NetfilterQueue...")
    finally:
        subprocess.call(['iptables', '-D', 'INPUT', '-j', 'NFQUEUE', '--queue-num', str(queue_num)])
        subprocess.call(['iptables', '-D', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', str(queue_num)])
