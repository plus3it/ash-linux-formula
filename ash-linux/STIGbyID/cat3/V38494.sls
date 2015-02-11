# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38494
# Finding ID:	V-38494
# Version:	RHEL-06-000028
# Finding Level:	Low
#
#     The system must prevent the root account from logging in from serial 
#     consoles. Preventing direct root login to serial port interfaces 
#     helps ensure accountability for actions taken on the systems using 
#     the root account.
#
############################################################

script_V38494-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38494.sh

{% if salt['file.search']('/etc/securetty','^ttyS') %}
replace_V38494-serialTTY:
  file.replace:
  - name: /etc/securetty
  - pattern: '^ttyS.*$'
  - repl: ''
{% else %}
replace_V38494-serialTTY:
  cmd.run:
  - name: 'echo "No serial console entries in /etc/securetty"'
{% endif %}
