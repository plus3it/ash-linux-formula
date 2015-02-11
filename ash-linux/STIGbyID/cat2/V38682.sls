# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38682
# Finding ID:	V-38682
# Version:	RHEL-06-000315
# Finding Level:	Medium
#
#     The Bluetooth kernel module must be disabled. If Bluetooth 
#     functionality must be disabled, preventing the kernel from loading 
#     the kernel module provides an additional safeguard against its 
#     activation.
#
#  CCI: CCI-000085
#  NIST SP 800-53 :: AC-19 c
#  NIST SP 800-53A :: AC-19.1 (iii)
#
############################################################

script_V38682-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38682.sh

{% if not salt['file.file_exists']('/etc/modprobe.d/bluetooth.conf') %}
file-V38682-touchRules:
  file.touch:
  - name: '/etc/modprobe.d/bluetooth.conf'
{% endif %}

file_V38682-appendBTblacklist:
  file.append:
  - name: /etc/modprobe.d/bluetooth.conf
  - text: 'install bluetooth /bin/false'

file_V38682-appendNPFblacklist:
  file.append:
  - name: /etc/modprobe.d/bluetooth.conf
  - text: 'install net-pf-31 /bin/false'

