import re
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from iptables import drop_packet

failed_attempts_ftp = defaultdict(list)
blocked_ips = set()
ftp_log_file = '/var/log/vsftpd.log'

def extract_timestamp(timestamp_str):
    timestamp = datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S %Y')
    return timestamp

def monitor_vsftpd_log():
    failed_login_pattern = re.compile(r'(\w{3} \w{3} \d+ \d+:\d+:\d+ \d+) \[pid \d+\] \[(?P<user>[^\]]+)\] FAIL LOGIN: Client "::ffff:(?P<ip>\d+\.\d+\.\d+\.\d+)"')
    current_time = datetime.now()

    process = subprocess.Popen(['tail', '-F', ftp_log_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while True:
        line = process.stdout.readline().decode('utf-8')
        if 'FAIL LOGIN' in line:
            match = failed_login_pattern.search(line)
            if match:
                timestamp_str = match.group(1)
                timestamp = extract_timestamp(timestamp_str)
                ip_address = match.group('ip')

                if ip_address in blocked_ips:
                    continue

                if(failed_attempts_ftp[ip_address]):
                    print(len(failed_attempts_ftp[ip_address]),' - ', current_time - failed_attempts_ftp[ip_address][0])
                failed_attempts_ftp[ip_address] = [ts for ts in failed_attempts_ftp[ip_address] if current_time - ts <= timedelta(hours=1)]
                print(len(failed_attempts_ftp[ip_address]))
                failed_attempts_ftp[ip_address].append(timestamp)
                print(len(failed_attempts_ftp[ip_address]))

                if len(failed_attempts_ftp[ip_address]) < 5:
                    print(f"Failed login attempt from IP: {ip_address} at {timestamp} - {len(failed_attempts_ftp[ip_address])}")
                elif len(failed_attempts_ftp[ip_address]) >= 5:
                    print(f"Blocking IP: {ip_address} due to repeated failed login attempts")
                    drop_packet(ip_address)
                    blocked_ips.add(ip_address)
                    del failed_attempts_ftp[ip_address]

if __name__ == "__main__":
    monitor_vsftpd_log()
