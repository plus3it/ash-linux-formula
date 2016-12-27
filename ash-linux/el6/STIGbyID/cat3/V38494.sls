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

{%- set stigId = 'V38494' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set cfgFile = '/etc/securetty' %}
{%- set srchPtn = 'ttyS' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.file.search(cfgFile, srchPtn) %}
replace_{{ stigId }}-serialTTY:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^{{ srchPtn }}.*$'
    - repl: ''

comment_{{ stigId }}-serialConf:
  file.comment:
    - name: '/etc/init/serial.conf'
    - regex: ^pre-start exec /sbin/securetty
    - char: '#'
    - require:
      - file: replace_{{ stigId }}-serialTTY

chattr_{{ stigId }}-serialConf:
  cmd.script:
    - name: 'V38494-serial_chattr.sh "/etc/init/serial.conf"'
    - source: 'salt://{{ helperLoc }}/V38494-serial_chattr.sh'
    - cwd: '/root'
    - stateful: True
    - require:
      - file: comment_{{ stigId }}-serialConf
{%- else %}
replace_{{ stigId }}-serialTTY:
  cmd.run:
    - name: 'echo "No serial console entries in {{ cfgFile }}"'
{%- endif %}
