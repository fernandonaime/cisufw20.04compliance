import os,time
from SUPPORT import y_n_choice
from datetime import datetime
def log_setup():
    global current_datetime
    log_file_path = "script_log.txt"
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not os.path.exists(log_file_path):
        with open(log_file_path, "w") as log_file:
            log_file.write(f"-----------------------------------------------------------------------\n")
            log_file.write(f"                           Host Firewall Compliance                         \n")
            log_file.write(f"-----------------------------------------------------------------------\n")

            log_file.write(f"{current_datetime} - ============ SCRIPT INITIATION ============\n")
    else:
        with open(log_file_path, "a") as log_file:
            log_file.write(f"\n{current_datetime} - ============ PROGRAM EXECUTION ============\n")


def Log_changes(changes):
    log_file_path = "script_log.txt"
    with open(log_file_path, "a") as log_file:
            log_file.write(f"\nChanges made: {changes}")

def retrieve_from_main_log(choice):
    try:
        control=["UFW INSTALLATION","IP-PERSISTENT","UFW-ENABLING","LOOPBACK-INTERFACE","OUTBOUND-RULES","PORT-RULES","DEFAULT-DENY-POLICY"]
        if choice is "date":
            main_log_filepath="script_log.txt"
            output_filepath=current_datetime+".txt"
            with open(main_log_filepath, 'r') as main_log_file:
                #gets the whole text file as lines
                lines = main_log_file.readlines()
            for index, line in enumerate(lines):
                if current_datetime in line:
                    with open(output_filepath, 'w') as output_file:
                        output_file.writelines(lines[index:])
                if current_datetime not in line:
                    print("No logs found for current_datetime")
        elif choice is "control":
            main_log_filepath="script_log.txt"
            #for loop to iterate through the list of controls
            i=0
            flag=False
            for i in range(len(control)):
                output_filepath=(control[i])+".txt"
                with open(main_log_filepath, 'r') as main_log_file:
                    #gets the whole text file as lines
                    lines = main_log_file.readlines()
                for index, line in enumerate(lines):
                    if control[i] in line:
                        with open(output_filepath, 'w') as output_file:
                            output_file.writelines(current_datetime+lines[index])
                            flag=True
            if flag:
                print("Log generated successfully")
            elif not flag:
                print("No configuration found for current_datetime")
        elif choice is None:
            print("Please choose either date or control")
            raise ValueError("Please choose either date or control")

    except ValueError as ve:
            print("Error:",ve)
    except TypeError as ve:
            print("Error:",ve)
    except AttributeError as ve:
            print("Error:",ve)

def Log_options_check():
    try:
        choice=input("""
        what type of log do you want,
         Date-wise
         Control-wise
        """).lower()
        if choice == 'date':
            retrieve_from_main_log("date")
        elif choice == 'control':
            retrieve_from_main_log("control")
        else:
            raise ValueError("Please choose either date or control")
    except ValueError as ve:
            print("Error:",ve)
    except TypeError as ve:
            print("Error:",ve)
    except AttributeError as ve:
            print("Error:",ve)

#function to generate different reports
def log_options():
    try:
        print("""
        \033[91m==================== Log Options ====================\033[0m""")
        print("\nDo you want to generate a log report")
        var=y_n_choice()
        var.lower()
        if var == 'y' or var == 'yes' or var == '':
            Log_options_check()
            print("\nExiting...")
        elif var == 'n' or var == 'no':
            print("\nExiting...")
            time.sleep(2)
        elif var is None:
            print("Error: Result is None.")
            return
    except ValueError as ve:
            print("Error:",ve)
    except TypeError as ve:
            print("Error:",ve)
    except AttributeError as ve:
            print("Error:",ve)

