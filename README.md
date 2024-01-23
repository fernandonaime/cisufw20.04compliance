# CIS Compliance Suite for Ubuntu Live Servers

## Overview

The CIS Compliance Suite is a collection of scripts dedicated to improving and managing the security configurations of Ubuntu Live Servers using Uncomplicated Firewall (UFW). The suite aligns with the Center for Internet Security (CIS) guidelines for secure system configurations.

## Features

- **Modularity:** The project adopts a modular structure for straightforward maintenance and scalability.
- **Logging:** Detailed logs are generated to monitor changes made during the configuration process.
- **Flexible Configuration:** Users can choose from various logging options, such as overall logs, control-wise logs, and date-wise logs.

## Getting Started

To run the CIS Compliance Suite on your Ubuntu Live Server, follow these steps:

1. Clone the repository:

    ```bash
    git clone https://github.com/fernandonaime/debian20.04compliance.git
    cd debian20.04compliance
    ```

2. Execute the main script with sudo:

    ```bash
    sudo python tester.py
    ```

3. Follow the on-screen instructions to harden the operating system.

## Project Structure

- `tester.py`: Main script for executing the UFW CIS Compliance Suite.
- `CIS_Ubuntu_Linux_20.04_LTS_Benchmark_v2.0.1-06-29-2023/`:
  - Contains CIS benchmark guidelines with automated and manual configuration steps.
  - The scripts in the suite automate certain tasks as per the CIS benchmarks.

## CIS Benchmark Guidelines (Example)

### 3.4.1.1 Ensure ufw is installed (Automated)

This control ensures that the Uncomplicated Firewall (UFW) is installed on the system.

### 3.4.1.2 Ensure iptables-persistent is not installed with ufw (Automated)

This control ensures that iptables-persistent is not installed alongside UFW.

### 3.4.1.3 Ensure ufw service is enabled (Automated)

This control ensures that the UFW service is enabled and set to start at boot.

### 3.4.1.4 Ensure ufw loopback traffic is configured (Automated)

This control ensures that UFW is configured to allow loopback traffic.

### 3.4.1.5 Ensure ufw outbound connections are configured (Manual)

This control requires manual configuration of UFW rules for outbound connections.

### 3.4.1.6 Ensure ufw firewall rules exist for all open ports (Automated)

This control ensures that UFW has firewall rules defined for all open ports.

### 3.4.1.7 Ensure ufw default deny firewall policy (Automated)

This control ensures that the UFW default firewall policy is set to deny.

## Contributors

- [fernandonaime](https://github.com/fernandonaime)
