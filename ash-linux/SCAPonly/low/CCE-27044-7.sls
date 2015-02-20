# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - sysctl_fs_suid_dumpable
#
# Security identifiers:
# - CCE-27044-7.sls
#
# Rule Summary: Disable core dumps for SUID programs
#
# Rule Text: The core dump of a setuid program is more likely to contain 
#            sensitive data, as the program itself runs with greater 
#            privileges than the user who initiated execution of the 
#            program. Disabling the ability for any setuid program to 
#            write a core file decreases the risk of unauthorized access 
#            of such data.
#
#################################################################

script_CCE-27044-7-describe:
  cmd.script:
    - source: salt://ash-linux/SCAPonly/low/files/CCE-27044-7.sh
    - cwd: '/root'

########################################
## RECOMMENDED REMEDIATION (from SCAP)
########################################
## # Set runtime for fs.suid_dumpable
## #
## sysctl -q -n -w fs.suid_dumpable=0
## 
## #
## # If fs.suid_dumpable present in /etc/sysctl.conf, change value to "0"
## #	else, add "fs.suid_dumpable = 0" to /etc/sysctl.conf
## #
## if grep --silent ^fs.suid_dumpable /etc/sysctl.conf ; then
## 	sed -i 's/^fs.suid_dumpable.*/fs.suid_dumpable = 0/g' /etc/sysctl.conf
## else
## 	echo "" >> /etc/sysctl.conf
## 	echo "# Set fs.suid_dumpable to 0 per security requirements" >> /etc/sysctl.conf
## 	echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
## fi
