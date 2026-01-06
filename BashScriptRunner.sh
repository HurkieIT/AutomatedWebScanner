#!/usr/bin/env bash

#___________________________________________________

#Launcher Automated scanner.
#Gemaakt door: Jens Cornelius Gijsbertus van den Hurk
#Datum: 6-1-2025

#_____________________________________________________

#Voor gebruiksgemak is deze scanner voorzien van een Bash script starter
# 1. Check Python 3

if command -v python3 &> /dev/null; then
    echo "Python version 3 is installed."
else
    echo  "Python version 3 is not installed."
    echo  "Install Python 3 to continue."
    exit 1
fi

# 2. Run dependency checker
python3 CheckScannerDependencies.py
exit_code=$?

echo "Dependency checker exit code: $exit_code"

if [ "$exit_code" -ne 0 ]; then
    echo "Dependencies not met. Scanner will NOT start."
    exit 1
fi

read -p "Press Enter to continue to the scanner..."

# 3. If all dependencies are met, run the Automated Scanner
python3 AutomatedScanner.py




