import csv
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from scapy.all import *

from scapy.layers import http
from iptables import drop_packet, is_ip_blocked
import protocol_mapping


#Global Variables.
n = 1
source_ip_packet_counts = defaultdict(lambda: deque(maxlen=1000))

def check_and_block_packets(source_ip, time_window_seconds, max_packet_count):
    # Get the current time
    current_time = datetime.now()
    
    packet_times = source_ip_packet_counts[source_ip]
    
    # Remove expired entries from the deque
    while packet_times and (current_time - packet_times[0] > timedelta(seconds=time_window_seconds)):
        packet_times.popleft()
    
    # Add the current packet time to the list
    source_ip_packet_counts[source_ip].append(current_time)
    
    # If the packet count exceeds the threshold within the time window, block the packets
    print("===",source_ip, '=\n', len(source_ip_packet_counts[source_ip]))
    if len(source_ip_packet_counts[source_ip]) > max_packet_count:
        print("Potential DoS attack detected from", source_ip, "within", time_window_seconds, "seconds. Dropping packets.")
        #drop_packet(source_ip)
        return 1

def match_snort_rule(packet_info, rule):
    rule_parts = re.split(r'[:)\s"]', rule)
    if len(rule_parts) >= 4 and (rule_parts[0] == "alert" or rule_parts[0] == "drop"):
        # Extract details from the Snort rule
        rule_proto = rule_parts[1]
        rule_src_ip = rule_parts[2]
        rule_src_port = rule_parts[3]
        rule_dst_ip = rule_parts[5]
        rule_dst_port = rule_parts[6]
        rule_threshold_flag = 0
        rule_content = None
        rule_flag = None
        
        if(rule.find("flags") != -1):
            rule_content = rule[rule.find('flags') +7]
        if (rule.find("content") != -1):
            rule_content = rule[rule.find("content") +10:rule.find('"',rule.find("content")+10)]
        
        
        
            #check_and_block_packets(packet_info["src_ip"], time_window_seconds=1, max_packet_count=5)
        if ((protocol_mapping.protocol_mapping[packet_info["protocol"]] == rule_proto or rule_proto == 'any') and (rule_src_ip == 'any' or rule_src_ip == packet_info["src_ip"]) and (rule_src_port == 'any' or rule_src_port == packet_info["src_port"]) and (rule_dst_ip == 'any' or rule_dst_ip == packet_info["dst_ip"]) and (rule_dst_port == 'any' or rule_dst_port == packet_info["dst_port"]) and (rule_flag==None or rule_flag==packet_info['flags']) and (rule_content == None or (rule_content in packet_info["payload"]) or (rule_content in packet_info["url"]))):
            
            #if (rule_content in packet_info["payload"]) if packet_info["payload"] else "":
            threshold_match = re.search(r'threshold: type threshold, track by_src, count (\d+), seconds (\d+)', rule)
            if threshold_match:
                count = int(threshold_match.group(1))
                seconds = int(threshold_match.group(2))
                rule_threshold_flag = check_and_block_packets(rule, time_window_seconds=seconds, max_packet_count=count)
                if(rule_threshold_flag != 1):
                    #print("=================")
                    return
            #print("rule matched : ",rule_content, " - ", rule_parts[0])
            if(rule_parts[0] == 'drop'):
                drop_packet(packet_info['src_ip'])


            start_index = rule.find('msg') + 5  # FiND The first occurrence of 'a'
            end_index = rule.find('"', start_index + 1)  # Find the next 'a' after the start index

            if start_index != -1 and end_index != -1:  # If both 'a's are found
                substring = rule[start_index + 1:end_index]
          
            file_path = 'alerts_log.csv'
            with open(file_path, 'r') as file:
                line_count = sum(1 for line in file) 
             
            with open(file_path, mode='a', newline='') as file:
                    #line_count = sum(1 for line in file) - 1
                current_time = datetime.now()
                rule_sid = rule[rule.find("sid:") + 4 : rule.find(';', rule.find('sid:'))]
                if(rule_sid[-1] == ')'):
                    rule_sid = rule_sid[0:-1]
                log = [[line_count, current_time,rule_parts[0], substring, rule_sid]]
                writer = csv.writer(file)
                writer.writerows(log)
            return 1;


def match_rules(packet_info):
    #if not is_ip_blocked(packet_info["src_ip"]):
    #print(is_ip_blocked(packet_info["src_ip"]))
    global n
    #print("----------------",n)
    n+=1
    #print(protocol_mapping.protocol_mapping[packet_info["protocol"]], "packet detected from ", packet_info["src_ip"],' to port:',packet_info['dst_port']," Flag:", packet_info['flags'], "\nwith payload: ", packet_info['payload'])
    #print("----------------")
    with open('rules.txt', 'r') as file:
    # Read the file line by line
        for line in file:
            str = line.strip()+" "
            if(str[0] != ' ' and str[0] != '#'):
                rule = str
                if(match_snort_rule(packet_info, rule) == 1):
                    break





def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def process_packet(packet):
    ip_layer = packet.getlayer("IP")
    tcp_layer = packet.getlayer("TCP")
    udp_layer = packet.getlayer("UDP")
    icmp_layer = packet.getlayer("ICMP")
    http_layer = packet.getlayer(http.HTTPRequest)

    packet_time = packet.time
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
        "time": packet_time,
        "url" : url,
    }

    if packet_info["src_ip"] and not is_ip_blocked(packet_info["src_ip"]):
        match_rules(packet_info)

# Start capturing packets on eth0 and process each packet
def start_sniffing():
    sniff(iface='eth0', prn=process_packet, store=0)
