import os
import subprocess
import sys


# --------------------------------------------------------------------------------------------------
def variables():
    usr_ufw_input = ''


# this code is to check if ufw is installed in the debian system or not
def is_ufw_installed():
    return bool(os.system("command -v ufw >/dev/null 2>&1") == 0)


def ensure_ufw_installed():
    if not is_ufw_installed():
        var = input("Do you want to install the Hoat firewall [Y/n] ?")
        if var == 'y':
            os.system("apt install ufw")
            print('ufw got installed now')
        else:
            exit()
    else:
        ensure_iptables_persistent_packages_removed()


def is_iptables_persistent_installed():
    return bool(os.system("dpkg -s iptables-persistent >/dev/null 2>&1") == 0)


def ensure_iptables_persistent_packages_removed():
    if is_iptables_persistent_installed():
        var = input("do you want to remove the iptable-persistant-packages")
        if var == 'y':
            os.system("apt purge iptables-persistent")
            print('iptables_persistant_packages_removed')
        else:
            exit()
    else:
        enable_firewall_sequence()


def is_ufw_tcp_rule_enabled():
    rule = "allow proto tcp from any to any port 22"
    command = ["sudo", "ufw", "status", "numbered"]

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print(f"Error: {error.decode('utf-8')}")
        return False

    for line in output.decode('utf-8').split('\n'):
        if rule in line:
            print(f"Rule found: {line}")
            return True

    print(f"Rule not found.")
    return False


def enable_firewall_sequence():
    if not is_ufw_tcp_rule_enabled():
        var = input("UFW is not enabled, do you want to enable it [Y/N] ")
        if var == 'y':
            print(
                "ufw will flush its chains.This is good in maintaining a consistent state, but it may drop existing connections (eg ssh)")
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
    print("..Enabling the firewall")
    os.system("ufw enable")


# def enable_firewall():
#     if check_ufw_rule() == False:
#             usr_enbFw_input=input("UFW is not enabled, do you want to enable it [Y/N] ")
#             switch(usr_enbFw_input)
#             def switch(para):
#                 if para == 'y':
#                     enable_firewall_sequence()
#                 elif para == 'n':
#                     usr_enbFw_input=input("this procecss is required before enabling the firewall, are you sure you want to end the configuration of the firewall [Y/n] ")
#                     if usr_enbFw_input=='n':
#                         enable_firewall_sequence()
#                     elif usr_enbFw_input=='n':
#                         exit()
#


def main():
    print(ensure_ufw_installed())

    # if is_ufw_installed() == False:
    #     usr_ufw_input=input("UFW is not installed do you want to install it [y/n] ")
    #     if usr_ufw_input=='y':
    #         ensure_ufw_installed()
    #     elif usr_ufw_input=='n':
    #         print("You proceeded with not installing the firewall")
    #         exit()
    # else:
    #     print("Ufw has been installed already")
    #     exit()


if __name__ == "__main__":
    main()

# do you want to enable the firewall?
# enabled

# active

# Status: active


# import subprocess
#
#
# check_ufw_rule()
#
#
# 1- check if the firewall is the firewall installed`
# 2-
