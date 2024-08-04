import os
import csv
from threading import Thread
from ssh_log import monitor_auth_log
from ftp_log import monitor_vsftpd_log
from process_packet import start_sniffing

def initialize_alerts_log():
    file_name = "alerts_log.csv"
    if not os.path.exists(file_name):
        data = [['Event', 'Time', 'Action', 'Msg', 'Sid']]
        with open(file_name, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(data)

if __name__ == "__main__":
    initialize_alerts_log()

    auth_log_thread = Thread(target=monitor_auth_log)
    auth_log_thread.daemon = True
    auth_log_thread.start()

    vsftpd_log_thread = Thread(target=monitor_vsftpd_log)
    vsftpd_log_thread.daemon = True
    vsftpd_log_thread.start()

    start_sniffing()

