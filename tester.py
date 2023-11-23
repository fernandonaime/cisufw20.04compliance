import os
import subprocess
import sys
import re


# --------------------------------------------------------------------------------------------------
def variables():
    usr_ufw_input = ''


# this code is to check if ufw is installed in the debian system or not
def is_ufw_installed():
    print("\n \n ================================Installing Host Firewall==================================="
          "\n A firewall utility is required to configure the Linux kernel's netfilter framework via the"
          "iptables or nftables back-end."
          "The Linux kernel's netfilter framework host-based firewall can protect against threats"
          "originating from within a corporate network to include malicious mobile code and poorly"
          "configured software on a host."
          "Note: Only one firewall utility should be installed and configured. UFW is dependent on"
          "the iptables package")
    return bool(os.system("command -v ufw >/dev/null 2>&1") == 0)


def ensure_ufw_installed():
    if not is_ufw_installed():
        var = input("\nDo you want to install the Host firewall [Y/n] ?")
        var.lower()
        if var == 'y':
            os.system("apt install ufw")
            print('\nufw got installed now')
        else:
            exit()
    else:
        print("\nYou have already installed the ufw")




def is_iptables_persistent_installed():
    print("\n \n ================================Removing IP-Persistent Tables==================================="
          "\n Running both ufw and the services included in the iptables-persistent package may lead "
          "to conflict.")
    return bool(os.system("dpkg -s iptables-persistent >/dev/null 2>&1") == 0)


def ensure_iptables_persistent_packages_removed():
    if is_iptables_persistent_installed():
        var = input("\n ...do you want to remove the iptable-persistant")
        var.lower()
        if var == 'y':
            os.system("apt purge iptables-persistent")
            print('\n ...iptables_persistant_packages_removed')
        else:
            print("configuration skipped")
    else:
        print("\n ...you have already removed the persistant tables")



def is_ufw_tcp_rule_enabled():
    print("\n \n ================================Enabling the UFW=================================="
          "\n When running ufw enable or starting ufw via its initscript, ufw will flush its chains."
           "This is required so ufw can maintain a consistent state, but it may drop existing"
           "connections (eg ssh). ufw does support adding rules before enabling the firewall"
           "The rules will still be flushed, but the ssh port will be open after enabling the"
           "firewall. Please note that once ufw is 'enabled', ufw will not flush the chains when"
           "adding or removing rules (but will when modifying a rule or changing the default"
           "policyBy default, ufw will prompt when enabling the firewall while running under ssh")

    rule = "allow proto tcp from any to any port 22"
    command = ["sudo", "ufw", "status", "numbered"]

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print("Error: {error.decode('utf-8')}")
        return False

    for line in output.decode('utf-8').split('\n'):
        if rule in line:
            print("Rule found: {line}")
            return True

    print("Rule not found.")
    return False


def enable_firewall_sequence():
    if not is_ufw_tcp_rule_enabled():
        var = input("\nUFW is not enabled, do you want to enable it [Y/N] ")
        var.lower()
        if var == 'y':
            print("\nufw will flush its chains.This is good in maintaining a consistent state, but it may drop existing connections (eg ssh)")
            os.system("ufw allow proto tcp from any to any port 22")
        else:
            exit()
    elif is_ufw_tcp_rule_enabled():
        exit()
    # Run the following command to verify that the ufw daemon is enabled:
    print(" \n ...verifying that the ufw daemon is enabled")
    os.system("systemctl is-enabled ufw.service")
    # following command to verify that the ufw daemon is active:
    print(" \n ...verifying that the ufw daemon is active:")
    os.system("systemctl is-active ufw")
    # Run the following command to verify ufw is active
    print(" \n ...verifying ufw is active")
    os.system("ufw status")
    # following command to unmask the ufw daemon
    print("\n ...unmasking ufw daemon")
    os.system("systemctl unmask ufw.service")
    # following command to enable and start the ufw daemon:
    print("\n ...enabling and starting the ufw daemon:")
    os.system("systemctl --now enable ufw.service")
    # ollowing command to enable ufw:
    print("\n..Enabling the firewall")
    os.system("ufw enable")



def ensure_loopback_configured():
    print("\n \n ================================Configuring the Loopback interface==================================="
          "\n Loopback traffic is generated between processes on machine and is typically critical to"
           "operation of the system. The loopback interface is the only place that loopback network"
           "(127.0.0.0/8 for IPv4 and ::1/128 for IPv6) traffic should be seen, all other interfaces"
           "should ignore traffic on this network as an anti-spoofing measure.")
    var = input("\n do you want to proceed [Y/n] ?")
    var.lower()
    if var == 'y':
        os.system("ufw allow in on lo")
        os.system("ufw allow out on lo")
        os.system("ufw deny in from 127.0.0.0/8")
        os.system("ufw deny in from ::1")
    else:
        print("\n Loopback interface not configured!!")



def ensure_ufw_outbound_connections():
    print("\n \n ================================Configuring ufw outbound connections ==================================="
          "\n If rules are not in place for new outbound connections all packets will be dropped by the"
           "default policy preventing network usage.")
    var = input("\n Do you want to configure your ufw outbound connections if this set of rules are not in place for new outbound connections all"
                "packets will be dropped by the"
                "default policy preventing network usage., [Y/n]")
    var.lower()
    if var == 'y':
        var = input("\n PLease verify all the rules whether it matches all the site policies")
        if var == 'y':
            print("\n implementing a policy to allow all outbound connections on all interfaces:")
            os.system("ufw allow out on all")
        else:
            print("\n ufw outbound configurations are not been configured")
    else:
        print("\n Hardening measure skipped")



def get_allow_deny():
    allw_dny = input("allow or deny: ")
    allw_dny.lower()
    return allw_dny


def get_bounds():
    bounds = input("inbound or outbound: ")
    bounds.lower()
    return bounds


def get_network_address():
    netadd = input("enter network address: ")
    netadd.lower()
    return netadd


def get_proto():
    proto = input("enter protocol tcp or udp: ")
    proto.lower()
    return proto


def get_mask():
    mask = input("enter the whole number value of the subnet mask: ")
    mask.lower()
    return mask


def ensure_rules_on_ports(script_path):
    print("\n \n ================================Configuring firewall rules exist for all open ports==================================="
          "\n To reduce the attack surface of a system, all services and ports should be blocked unless required.")
    result = subprocess.run(['bash', script_path], capture_output=True, text=True)
    ports_list = 0
    if result.returncode == 0:
        # If the script ran successfully, print the output
        # getting numbers from string
        temp = re.findall(r'\d+', result.stdout)
        ports_list = list(map(int, temp))
        print("\nOpen ports with no FW rule")
        for i in range(0, len(ports_list)):
            print(i, '->', ports_list[i])

        p_no = int(input("please enter the index number of the intended port to be configured: "))
        port_number = ports_list[p_no]
        print("\nYour configuration will be commanded according to this format"
              "ufw-allow-from-192.168.1.0/24-to-any-proto-tcp-port-443" "\n \n" "Press enter to continue [enter]: ")
        input()
        allow = get_allow_deny()
        netad = get_network_address()
        proto = get_proto()
        mask = get_mask()
        rule = ("ufw " + allow + " from " + netad + "/" + mask + " to any proto " + proto + " port " + str(port_number))
        print(rule, '\n \nhit enterto continue [enter]')
        input()
        os.system(rule)
        input("\nHit enter to continue [enter]")

    else:
        # If there was an error, print the error message
        print("Error:")
        print(result.stderr)



def is_ufw_deny_policy():
    var=input("\n \n ================================default port deny policy==================================="
          "\n Any port and protocol not explicitly allowed will be blocked."
          "\nDo you want to configure default deny policy? [Y/n] ")
    var.lower()
    if var=='y':
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
# ufw default deny incoming
# ufw default deny outgoing
# ufw default deny routed
#==========================================================Configuring NF Tables======================================


def all_ufw_hardening_controls():
    ensure_ufw_installed()
    enable_firewall_sequence()
    ensure_iptables_persistent_packages_removed()
    script_path = 'ufwropnprts.sh'
    ensure_rules_on_ports(script_path)
    ensure_port_deny_policy()

def main():
    all_ufw_hardening_controls()


if __name__ == "__main__":
    main()
