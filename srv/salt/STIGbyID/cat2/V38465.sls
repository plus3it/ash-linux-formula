# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38465
# Finding ID:	V-38465
# Version:	RHEL-06-000045
# Finding Level:	Medium
#
#     Library files must have mode 0755 or less permissive. Files from 
#     shared library directories are loaded into the address space of 
#     processes (including privileged ones) or of the kernel itself at 
#     runtime. Restrictive permissions are necessary to protect ...
#
############################################################

script_V38465-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38465.sh

# Salt-friendly remediation-method being researched
