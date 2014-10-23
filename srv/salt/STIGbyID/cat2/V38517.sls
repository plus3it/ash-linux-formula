# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38517
# Finding ID:	V-38517
# Version:	RHEL-06-000127
# Finding Level:	Medium
#
#     The Transparent Inter-Process Communication (TIPC) protocol must be 
#     disabled unless required. Disabling TIPC protects the system against 
#     exploitation of any flaws in its implementation.
#
############################################################

script_V38517-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38517.sh

{% if not salt['file.file_exists']('/etc/modprobe.d/tipc.conf') %}
file-V38517-touchRules:
  file.touch:
  - name: '/etc/modprobe.d/tipc.conf'
{% endif %}

file_V38517-appendBlacklist:
  file.append:
  - name: /etc/modprobe.d/tipc.conf
  - text: 'install tipc /bin/false'

