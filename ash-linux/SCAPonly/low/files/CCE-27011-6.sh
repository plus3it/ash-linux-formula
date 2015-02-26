#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-27011-6
#
# Rule ID: bootloader_nousb_argument
#
# Rule Summary: Disable Kernel Support for USB via Bootloader Configuration
#
# Rule Text: Disabling the USB subsystem within the Linux kernel at 
#            system boot will protect against potentially malicious USB 
#            devices, although it is only practical in specialized 
#            systems.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Add 'nousb' option to the kernel"
diag_out "  line of the GRUB config file"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

