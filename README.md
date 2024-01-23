#CIS Compliance Suite

## Overview

The CIS Compliance Suite is a set of scripts designed to enhance and manage the security configurations of a Linux system using Uncomplicated Firewall (UFW). The suite follows the Center for Internet Security (CIS) guidelines for secure system configurations.

## Features

- **Modularity:** The project is structured into functional modules for easy maintenance and extensibility.
- **Logging:** Detailed logs are maintained to track changes made during the configuration process.
- **Flexible Configuration:** Users can choose different logging options, including an overall log, control-wise logs, and date-wise logs.

## Project Structure

- `tester.py`: Main script to execute the UFW CIS Compliance Suite.
- CIS Ubuntu Linux 20.04 LTS Benchmark v2.0.1 - 06-29-2023
    3.4.1.1 Ensure ufw is installed (Automated)
    3.4.1.2 Ensure iptables-persistent is not installed with ufw (Automated)
    3.4.1.3 Ensure ufw service is enabled (Automated)
    3.4.1.4 Ensure ufw loopback traffic is configured (Automated)
    3.4.1.5 Ensure ufw outbound connections are configured (Manual)
    3.4.1.6 Ensure ufw firewall rules exist for all open ports (Automated)
    3.4.1.7 Ensure ufw default deny firewall policy (Automated)
