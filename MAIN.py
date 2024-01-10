# Autor: P. NEMASHA FERNANDO
# Date: 2024-01-24
# Version: 1.0.0
# Description: Main file for the UFW CIS Compliance Suite
# Usage: python3 MAIN.py
# Notes: This file is the main file for the UFW CIS Compliance Suite for Ubuntu 20.04 Live Server and Desktop Editions,
# and it is the main file to be executed. This file will call the other files and functions in the suite.
# This file will also call the UFW.py file which will call the UFW functions.
# This file will also call the LOGGING.py file which will call the LOGGING functions.
# This file will also call the SCAN_OR_CONFIG.py file which will call the SCAN_OR_CONFIG functions.
# Python_version: 3.6.9
# ======================================================================================================================
from Utilities.SCAN_OR_CONFIG import *
from Utilities.LOGGING import *
from UFW import *


def main():
    try:
        log_setup()
        scan_or_config()
        log_options()
    except FileNotFoundError:
        noufwbanner()
    except KeyboardInterrupt:
        print("\n\nExited unexpectedly...")

if __name__ == "__main__":
    main()
