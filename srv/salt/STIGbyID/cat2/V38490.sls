# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38490
# Finding ID:	V-38490
# Version:	RHEL-06-000503
# Finding Level:	Medium
#
#     The operating system must enforce requirements for the connection of 
#     mobile devices to operating systems. USB storage devices such as 
#     thumb drives can be used to introduce unauthorized software and other 
#     vulnerabilities. Support for these devices should be disabled and the 
#     devices themselves should be ...
#
############################################################

script_V38490-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38490.sh

{% if salt['file.file_exists']('/etc/modprobe.conf') %}
file_V38490-replModprobe:
  file.replace:
  - name: /etc/modprobe.conf
  - pattern: "^install usb-storage"
  - repl: "install usb-storage /bin/true"
{% endif %}

{% if not salt['file.file_exists']('/etc/udev/rules.d/99-usb.rules') %}
file-V38490-touchRules:
  file.touch:
  - name: '/etc/udev/rules.d/99-usb.rules'
{% endif %}

file_V38490-appendRules:
  file.append:
  - name: /etc/udev/rules.d/99-usb.rules
  - text: 'ACTION=="add|change", BUS=="usb", SUBSYSTEMS=="usb", DRIVERS=="usb", OPTIONS:="ignore_device"'

{% if salt['file.file_exists']('/etc/modprobe.d/blacklist.conf') %}
file_V38490-appendBlacklist:
  file.append:
  - name: /etc/modprobe.d/blacklist.conf
  - text: 'blacklist usb_storage'
{% endif %}
