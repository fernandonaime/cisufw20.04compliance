import os
import subprocess
import sys
import re
import time
from datetime import datetime


# --------------------------------------------------------------------------------------------------
def log_setup():
    log_file_path = "script_log.txt"
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not os.path.exists(log_file_path):
        with open(log_file_path, "w") as log_file:
            log_file.write(f"{current_datetime} - LOG CREATED.")
    else:
        with open(log_file_path, "a") as log_file:
            log_file.write(f"{current_datetime} - PROGRAM EXECUTION")


def log_changes(changes):
    log_file_path = "script_log.txt"
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file_path, "a") as log_file:
            log_file.write(f"Changes made: {changes}")




def is_ufw_installed():
    print("""
\033[91m=============== Installing Host Firewall ===============\033[0m

A firewall utility is required to configure the Linux kernel's netfilter framework via the
iptables or nftables back-end. The Linux kernel's netfilter framework host-based firewall can
protect against threats originating from within a corporate network, including malicious
mobile code and poorly configured software on a host.

Note: Only one firewall utility should be installed and configured. UFW is dependent on
the iptables package.
""")
    return bool(os.system("command -v ufw >/dev/null 2>&1") == 0)


def ensure_ufw_installed():
    if not is_ufw_installed():
        var = input("\nThis point onwards,the configurations require the installation of ufw Do you want to install the Host firewall [Y/n] ?")
        var.lower()
        if var == 'y' or var == 'yes' or var == '':
            os.system("apt install ufw")
            line="Installed UFW"
            log_changes(line)
            print("\n",line)
        elif var == 'n' or var == 'no':
            line="UFW not installed"
            log_changes(line)
            print("\n",line)
            exit()
    else:
        line="UFW already installed"
        log_changes(line)
        print("\n",line)

def is_iptables_persistent_installed():
    print("""
\033[91m============== Removing IP-Persistent Tables ==============\033[0m

Running both `ufw` and the services included in the `iptables-persistent` package may lead
to conflicts.
""")
    return bool(os.system("dpkg -s iptables-persistent >/dev/null 2>&1") == 0)


def ensure_iptables_persistent_packages_removed():
    if is_iptables_persistent_installed():
        var = input("\n ...do you want to remove the iptable-persistant [Y/n]: ")
        var.lower()
        if var == 'y' or var == 'yes' or var == '':
            os.system("apt purge iptables-persistent")
            line="Iptables persistant packages removed"
            log_changes(line)
            print("\n",line)
        elif var == 'n' or var == 'no':
            line="Iptables persistant packages skipped by user"
            log_changes(line)
            print("\n",line)
    else:
        line="Iptables persistant packages already uninstalled "
        log_changes(line)
        print("\n",line)



def is_ufw_enabled():
    print("""
\033[91m================== Enabling UFW ==================\033[0m

When running `ufw enable` or starting `ufw` via its initscript, `ufw` will flush its chains.
This is required so `ufw` can maintain a consistent state, but it may drop existing
connections (e.g., SSH). `ufw` does support adding rules before enabling the firewall.
The rules will still be flushed, but the SSH port will be open after enabling the
firewall.

Please note that once `ufw` is 'enabled', it will not flush the chains when
adding or removing rules (but will when modifying a rule or changing the default policy).

By default, `ufw` will prompt when enabling the firewall while running under SSH.
""")

    try:
        # Run the command to check UFW status
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True)

        # Check if the output contains 'Status: active'
        return 'Status: active' in result.stdout
    except subprocess.CalledProcessError as e:
        # If an error occurs while running the command
        print(f"Error: {e}")
        return False


def enable_firewall_sequence():
    if not is_ufw_enabled():
        var = input("\nUFW is not enabled, do you want to enable it [Y/N] ")
        var.lower()
        if var == 'y' or var == 'yes' or var == '':
            print("\nufw will flush its chains.This is good in maintaining a consistent state, but it may drop existing connections (eg ssh)")
            os.system("ufw allow proto tcp from any to any port 22")
            # Run the following command to verify that the ufw daemon is enabled:
            print(" \n...verifying that the ufw daemon is enabled")
            os.system("systemctl is-enabled ufw.service")
            # following command to verify that the ufw daemon is active:
            print(" \n...verifying that the ufw daemon is active:")
            os.system("systemctl is-active ufw")
            # Run the following command to verify ufw is active
            print(" \n...verifying ufw is active")
            os.system("ufw status")
            # following command to unmask the ufw daemon
            print("\n...unmasking ufw daemon")
            os.system("systemctl unmask ufw.service")
            # following command to enable and start the ufw daemon:
            print("\n...enabling and starting the ufw daemon:")
            os.system("systemctl --now enable ufw.service")
            #following command to enable ufw:
            print("\n..Enabling the firewall")
            os.system("ufw enable")
            line="""
            Commands issued before enabling the firewall:
                ufw allow proto tcp from any to any port 22
                systemctl is-enabled ufw.service
                systemctl is-active ufw
                systemctl unmask ufw.service
                systemctl --now enable ufw.service
            ufw enable
            """
            log_changes(line)
            print("\n",line)
        elif var == 'n' or var == 'no':
            line="User didn't enable the UFW service"
            log_changes(line)
            print("\nExiting UFW enabling mode... continuing to next configurations")
    else:
        line="UFW is already enabled"
        log_changes(line)
        print("\n",line)





def ensure_loopback_configured():
    print("""
    \033[91m================ Configuring the Loopback Interface =================\033[0m

Loopback traffic is generated between processes on the machine and is typically critical to
the operation of the system. The loopback interface is the only place that loopback network
(127.0.0.0/8 for IPv4 and ::1/128 for IPv6) traffic should be seen. All other interfaces
should ignore traffic on this network as an anti-spoofing measure.
""")
    var = input("\n do you want to proceed [Y/n] ?")
    var.lower()
    if var == 'y' or var == 'yes' or var == '':
        line="""
        User enabled configuring lo interfaces,
        Commands executed when configuring loopback interfaces:
            ufw allow in on lo
            ufw allow out on lo
            ufw deny in from 127.0.0.0/8
            ufw deny in from ::1
            
        """
        log_changes(line)
        print("\nEnabling configurations on lo interfaces...")
        os.system("ufw allow in on lo")
        os.system("ufw allow out on lo")
        os.system("ufw deny in from 127.0.0.0/8")
        os.system("ufw deny in from ::1")
    elif var == 'n' or var == 'no':
        line="Loopback interface not configured"
        log_changes(line)
        print("\n",line)


def ensure_ufw_outbound_connections():
    print("""
\033[91m========= Configuring UFW Outbound Connections =========\033[0m

If rules are not in place for new outbound connections, all packets will be dropped by the
default policy, preventing network usage.
""")
    var = input("\n Do you want to configure your ufw outbound connections if this set of rules are not in place for new outbound connections all"
                "packets will be dropped by the"
                "default policy preventing network usage., [Y/n]")
    var.lower()
    if var == 'y' or var == 'yes' or var == '':
        # var = input("\n PLease verify all the rules whether it matches all the site policies")
        print("\n implementing a policy to allow all outbound connections on all interfaces:")
        line="""
        User enabled configuring UFW outbound connections,
        below Commands executed when configuring outbound interfaces:
            ufw allow out on all
        """
        log_changes(line)
        print("\nConfiguration successfull ...")
        os.system("ufw allow out on all")

    elif var == 'n' or var == 'no':
        line="User skipped the ufw outbound configurations"
        log_changes(line)
        print("\n Hardening measure skipped")


def get_allow_deny():
    while True:
        try:
            allw_dny = input("Enter rule (allow or deny): ").lower()
            if allw_dny not in ['allow', 'deny']:
                raise ValueError("Invalid rule. Please enter either 'allow' or 'deny'.")

            return allw_dny
        except ValueError as ve:
            print("Error:",ve)


def is_valid_decimal(value):
    return 0 <= int(value) <= 255

def is_valid_network_address(address_parts):
    return all(is_valid_decimal(part) for part in address_parts)

def get_network_address():
    while True:
        try:
            netadd = input("\nEnter network address (in the format xxx.xxx.xxx.xxx): ")
            address_parts = netadd.split('.')

            # Use a regular expression to check if the input matches the expected format
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', netadd) or not is_valid_network_address(address_parts):
                raise ValueError("Invalid network address format or out-of-range values. Please use xxx.xxx.xxx.xxx format.")

            return netadd
        except ValueError as ve:
             print("\nError:", ve)

def get_proto():
    while True:
        try:
            proto = input("Enter protocol (tcp or udp): ").lower()
            if proto not in ['tcp', 'udp']:
                raise ValueError("Invalid protocol. Please enter either 'tcp' or 'udp'.")

            return proto
        except ValueError as ve:
            print("Error:",ve)

def get_mask():
    while True:
        try:
            mask = int(input("\nEnter the whole number value of the subnet mask (16-32): "))
            if 16 <= mask <= 32:
                return str(mask)
            else:
                raise ValueError("\nInvalid subnet mask. Please enter a value between 16 and 32.")
        except ValueError as ve:
            print("\nError:",ve)

def get_ports_as_a_list(script_path):
    result = subprocess.run(['bash', script_path], capture_output=True, text=True)
    ports_list = 0
    if result.returncode == 0:
        # If the script ran successfully, print the output
        # getting numbers from string
        temp = re.findall(r'\d+', result.stdout)
        ports_list = list(map(int, temp))
        print("Open ports with no FW rule")
        for i in range(0, len(ports_list)):
            print(i, ':', ports_list[i])
        return ports_list

    else:
        # If there was an error, print the error message
        print("Error:")
        print(result.stderr)


def get_port_number(script_path):
    while True:
        try:
            ports_list=get_ports_as_a_list(script_path)
            p_no = int(input("Enter the index number of the port to be configured: "))
            if 0 <= p_no <= len(ports_list)-1:
                port_number = ports_list[p_no]
                return str(port_number)
            else:
                raise ValueError("\nInvalid Index Number. Please enter a value between 0 and",len(ports_list))
        except ValueError as ve:
            print("\nError:",ve)

def ensure_rules_on_ports(script_path):
    print("""
\033[91m=== Configuring Firewall Rules for All Open Ports ===\033[0m

To reduce the attack surface of a system, all services and ports should be blocked unless required.

Your configuration will follow this format:
    ufw allow from 192.168.1.0/24 to any proto tcp port 443

""")
    var=input("Do you want to continue configuring firewall rules for all ports [Y/n]: ").lower()
    if var == 'y' or var == 'yes' or var == '':
        port_number=get_port_number(script_path)
        allow = get_allow_deny()
        netad = get_network_address()
        proto = get_proto()
        mask = get_mask()
        rule = ("ufw " + allow + " from " + netad + "/" + mask + " to any proto " + proto + " port " + str(port_number))
        line=("User configured the follwing port rule\n: "+str(rule))
        log_changes(line)
        os.system(rule)
        input("\nHit enter to continue [enter]")
        input()
    elif var == 'n' or var == 'no':
        line=("User did not configure firewall rules on ports")
        log_changes(line)
        print("Skipping firewall rule configuration on ports...")


def ensure_port_deny_policy():
    var = input("""
\033[91m================ Default Port Deny Policy ================\033[0m

Any port and protocol not explicitly allowed will be blocked.

Do you want to configure the default deny policy? [Y/n]: """)

    var.lower()
    if var == 'y' or var == 'yes' or var == '':
        print("...remediation process...")
        print("\n allowing Git...")
        os.system("ufw allow git")
        print("\n allowing http in...")
        os.system("ufw allow in http")
        print("\n allowing http out...")
        os.system("ufw allow out http")
        print("\n allowing https in...")
        os.system("ufw allow in https")
        print("\n allowing https out...")
        os.system("ufw allow out https")
        print("\n allowing port 53 out...")
        os.system("ufw allow out 53")
        print("\n allowing ufw logging on...")
        os.system("ufw logging on")
        print("\n denying incoming by default...")
        os.system("ufw default deny incoming")
        print("\n denying outgoing by default...")
        os.system("ufw default deny outgoing")
        print("\n denying default routing...")
        os.system("ufw default deny routed")
        line="""
        User configured the following default deny policies:
            ufw allow git
            ufw allow in http
            ufw allow out http
            ufw allow in https
            ufw allow out https
            ufw allow out 53
            ufw logging on
            ufw default deny incoming
            ufw default deny outgoing
            ufw default deny routed
        """
        log_changes(line)
    elif var == 'n' or var == 'no':
        line="User skipped configuring default deny policy"
        log_changes(line)
        print("\n exiting port deny policy")




#==========================================================Configuring NF Tables======================================









#========================================================== M A I N ======================================
def all_ufw_hardening_controls():
    ensure_ufw_installed()
    time.sleep(2)
    ensure_iptables_persistent_packages_removed()
    time.sleep(2)
    enable_firewall_sequence()
    time.sleep(2)
    script_path = 'ufwropnprts.sh'
    ensure_rules_on_ports(script_path)
    time.sleep(2)
    ensure_port_deny_policy()
    time.sleep(2)


def main():
    try:
        log_setup()
        all_ufw_hardening_controls()
        print("\n \033[91mPress enter to exit the code [enter] \033[0m")
        input()
        print("\nExiting...")
        time.sleep(2)
    except KeyboardInterrupt:
        print("\n\nExiting the application !")



if __name__ == "__main__":
    main()
