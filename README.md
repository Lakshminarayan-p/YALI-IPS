# YALI-IPS

YALI (Yet Another Layer of Intrusion prevention) is a robust Intrusion Prevention System (IPS) designed to monitor, detect, and prevent malicious activities on a network. This project focuses on providing security for network traffic by analyzing packets, applying rules, and logging alerts.

## Features

- **Packet Inspection**: Analyze network packets to identify and block malicious activities.
- **Custom Rules**: Define custom rules for traffic filtering and anomaly detection.
- **Protocol Mapping**: Supports protocol mapping for more accurate packet analysis.
- **Logging**: Detailed logging of alerts and detected anomalies.
- **FTP and SSH Monitoring**: Specific modules for monitoring FTP and SSH traffic.

## Project Structure

- `main.py`: The main entry point of the IPS.
- `process_packet.py`: Handles packet processing and inspection.
- `protocol_mapping.py`: Maps protocols to ensure accurate packet analysis.
- `iptables.py`: Manages IP tables for traffic filtering.
- `ftp_log.py`: Monitors and logs FTP traffic.
- `ssh_log.py`: Monitors and logs SSH traffic.
- `rules.txt`: Defines rules for packet inspection.
- `alerts_log.csv`: Logs of all alerts generated by the IPS.

## Requirements

### Programming Language:
- **Python**

### Python Libraries:
- **subprocess**: For spawning new processes and connecting to their input/output/error pipes.
- **re**: For regular expression matching operations.
- **collections**: For specialized data structures.
- **datetime**: For date and time manipulation.
- **csv**: For handling CSV file operations.
- **os**: For interacting with the operating system.
- **scapy**: For network packet manipulation and analysis.
- **threading**: For parallel execution of threads.
- **iptables**: For managing and configuring IP tables.

### Tools:
- **IPTables**: A command-line firewall utility that manages network traffic.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Lakshminarayan-p/YALI-IPS.git
    cd YALI-IPS
    ```

2. Install the necessary Python libraries:

    ```bash
    pip install scapy
    ```

3. Run the main script:

    ```bash
    python3 main.py
    ```

## Usage

- Customize the `rules.txt` file to define the behavior of the IPS.
- Monitor the `alerts_log.csv` file for any detected anomalies or attacks.

## Contributing

This project was developed collaboratively by a dedicated team. Contributions are welcome from all team members. If you have suggestions for improvements or find any issues, please communicate with the team, and we can work together to enhance the project.

## Contact

For any queries, please reach out to [Lakshmi Narayan.P](mailto:lakshminarayan15903@gmail.com).
