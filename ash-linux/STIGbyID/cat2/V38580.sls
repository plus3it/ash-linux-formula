# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38580
# Finding ID:	V-38580
# Version:	RHEL-06-000202
# Finding Level:	Medium
#
#     The audit system must be configured to audit the loading and 
#     unloading of dynamic kernel modules. The addition/removal of kernel 
#     modules can be used to alter the behavior of the kernel and 
#     potentially introduce malicious code into kernel space. It is 
#     important to have an audit trail of modules ...
#
#  CCI: CCI-000172
#  NIST SP 800-53 :: AU-12 c
#  NIST SP 800-53A :: AU-12.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-12 c
#
############################################################
script_V38580-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38580.sh

{% if grains['cpuarch'] == 'x86_64' %}
file_V38580-appendModchk:
  file.append:
    - name: /etc/audit/audit.rules
    - text:
      - ' '
      - '# Monitor dynamic kernel module (un)load (per STIG-ID V-38580/RHEL-06-000202)'
      - '-w /sbin/insmod -p x -k modules'
      - '-w /sbin/rmmod -p x -k modules'
      - '-w /sbin/modprobe -p x -k modules'
      - '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules'
{% endif %}
