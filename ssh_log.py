import re
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone

failed_attempts = defaultdict(list)
auth_log_file = '/var/log/auth.log'

def extract_timestamp_auth(timestamp_str):
    timestamp = datetime.strptime(timestamp_str.split('.')[0], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    return timestamp

def block_ip_address(ip_address):
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])

def monitor_auth_log():
    failed_login_pattern = re.compile(r'Failed password for .+ from (\d+\.\d+\.\d+\.\d+)')
    current_time = datetime.now(timezone.utc)

    process = subprocess.Popen(['tail', '-F', auth_log_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while True:
        line = process.stdout.readline().decode('utf-8')
        if 'Failed password' in line:
            match = failed_login_pattern.search(line)
            if match:
                ip_address = match.group(1)
                timestamp = extract_timestamp_auth(line)

                failed_attempts[ip_address] = [ts for ts in failed_attempts[ip_address] if current_time - ts <= timedelta(hours=1)]
                failed_attempts[ip_address].append(timestamp)

                if len(failed_attempts[ip_address]) >= 5:
                    block_ip_address(ip_address)
                    del failed_attempts[ip_address]
