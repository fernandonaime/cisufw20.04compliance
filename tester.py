import os
import subprocess
import sys
import re
import time


# --------------------------------------------------------------------------------------------------
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
        if var == 'y'or'yes'or'':
            os.system("apt install ufw")
            print('\nufw got installed now')
        else:
            print('\nNot installing ufw! ')
    else:
        print("you have already installed the ufw...")

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
        if var == 'y'or'yes'or'':
            os.system("apt purge iptables-persistent")
            print('\n ...iptables_persistant_packages_removed')
        else:
            print("configuration skipped")
    else:
        print("you have already removed the persistant tables...")



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
        if var == 'y'or'yes'or'':
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
        else:
            print("\nExiting UFW enabling mode... continuing to next configurations")
    else:
        print("UFW is already enabled...")




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
    if var == 'y'or'yes'or'':
        os.system("ufw allow in on lo")
        os.system("ufw allow out on lo")
        os.system("ufw deny in from 127.0.0.0/8")
        os.system("ufw deny in from ::1")
    else:
        print("\n Loopback interface not configured!!")



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
    if var == 'y'or'yes'or'':
        var = input("\n PLease verify all the rules whether it matches all the site policies")
        if var == 'y':
            print("\n implementing a policy to allow all outbound connections on all interfaces:")
            os.system("ufw allow out on all")
        else:
            print("\n ufw outbound configurations are not been configured")
    else:
        print("\n Hardening measure skipped")



# def get_allow_deny():
#     allw_dny = input("allow or deny: ")
#     allw_dny.lower()
#     return allw_dny
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

Press Enter to continue [enter]:
""")
    input()
    port_number=get_port_number(script_path)
    allow = get_allow_deny()
    netad = get_network_address()
    proto = get_proto()
    mask = get_mask()
    rule = ("ufw " + allow + " from " + netad + "/" + mask + " to any proto " + proto + " port " + str(port_number))
    os.system(rule)
    input("\nHit enter to continue [enter]")




def is_ufw_deny_policy():
    var = input("""
\033[91m================ Default Port Deny Policy ================\033[0m

Any port and protocol not explicitly allowed will be blocked.

Do you want to configure the default deny policy? [Y/n]: """)

    var.lower()
    if var=='y'or'yes'or'':
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
    else:
        print("\n exiting port deny policy")
        exit()
def ensure_port_deny_policy():
    is_ufw_deny_policy()
    print("\n denying incoming by default...")
    os.system("ufw default deny incoming")
    print("\n denying outgoing by default...")
    os.system("ufw default deny outgoing")
    print("\n denying default routing...")
    os.system("ufw default deny routed")

#==========================================================Configuring NF Tables======================================









#========================================================== M A I N ======================================
def all_ufw_hardening_controls():
    try:
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
        print("Press enter to exit the code [enter] ")
        input()
        print("\nExiting...")
        time.sleep(2)
    except KeyboardInterrupt:
        print("\n\nExiting the application !")

def main():
    all_ufw_hardening_controls()



if __name__ == "__main__":
    main()
