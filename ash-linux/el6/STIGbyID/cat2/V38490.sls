# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38490
# Finding ID:	V-38490
# Version:	RHEL-06-000503
# Finding Level:	Medium
#
#     The operating system must enforce requirements for the connection of 
#     mobile devices to operating systems. USB storage devices such as 
#     thumb drives can be used to introduce unauthorized software and other 
#     vulnerabilities. Support for these devices should be disabled and the 
#     devices themselves should be tightly controlled.
#
#  CCI: <None specified in DISA documentation>
#  NIST SP 800-53 :: <None specified in DISA documentation>
#
############################################################

{%- set stig_id = '38490' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set file_modprobe = '/etc/modprobe.conf' %}
{%- set file_modprobe_usb = '/etc/modprobe.d/usb.conf' %}
{%- set file_99usb_rules = '/etc/udev/rules.d/99-usb.rules' %}
{%- set file_modprobe_blacklist = '/etc/modprobe.d/blacklist.conf' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

{%- if salt.file.file_exists('{{ file_modprobe }}') %}
file_V{{ stig_id }}-replModprobe:
  file.replace:
    - name: /etc/modprobe.conf
    - pattern: "install usb-storage .*$"
    - repl: "install usb-storage /bin/true"
    - onlyif:
      - 'grep -E -e "usb-storage" {{ file_modprobe }}'
{%- else %}
file_V{{ stig_id }}-touchUSBconf:
  file.touch:
    - name: '{{ file_modprobe_usb }}'
file_V{{ stig_id }}-appendUSBconf:
  file.append:
    - name: '{{ file_modprobe_usb }}'
    - text: 'install usb-storage /bin/true'
    - require:
      - file: file_V{{ stig_id }}-touchUSBconf
    - onlyif:
      - 'test -f {{ file_modprobe_usb }}'
{%- endif %}

file_V{{ stig_id }}-touchRules:
  file.touch:
    - name: '{{ file_99usb_rules }}'

file_V{{ stig_id }}-appendRules:
  file.append:
    - name: '{{ file_99usb_rules }}'
    - text: 'ACTION=="add|change", BUS=="usb", SUBSYSTEMS=="usb", DRIVERS=="usb", OPTIONS:="ignore_device"'
    - require:
      - file: file_V{{ stig_id }}-touchRules
    - onlyif:
      - 'test -f {{ file_99usb_rules }}'

file_V{{ stig_id }}-appendBlacklist:
  file.append:
    - name: '{{ file_modprobe_blacklist }}'
    - text: 'blacklist usb_storage'
    - onlyif:
      - 'test -f {{ file_modprobe_blacklist }}'
