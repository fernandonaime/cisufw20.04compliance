from UFW import*
#function to ask the user if he wants to do a scan or go straight into configurations and call the relevant function in the script and exit if needed
def scan_or_config():
    print("""
    \033[91m==================== UFW CIS Compliance Suite ====================\033[0m""")
    print("\nDo you want to scan your system configurations press no to continue configuring: ")
    var=y_n_choice()
    var.lower()
    if var == 'y' or var == 'yes' or var == '':
        scan_system_configuration()
        print("\nExiting...")
        time.sleep(2)
        #ask the user if he needs to do the configurations
        print("\nDo you want to continue to configurations")
        var=y_n_choice()
        var.lower()
        if var == 'y' or var == 'yes' or var == '':
            all_ufw_hardening_controls()
            print("\n\033[91mPress enter to exit the code [enter] \033[0m")
            input()
            print("\nExiting...")
            time.sleep(2)
        if var == 'n' or var == 'no':
            print("\nExiting...")
            time.sleep(2)
        elif var is None:
            print("Error: Result is None.")
            return
    elif var == 'n' or var == 'no':
        print("\nContinuing to configurations...")
        all_ufw_hardening_controls()
        time.sleep(2)
        return
    elif var is None:
        print("Error: Result is None.")
        return
