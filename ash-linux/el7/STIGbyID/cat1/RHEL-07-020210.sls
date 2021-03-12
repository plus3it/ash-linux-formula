# Finding ID:	RHEL-07-020210
# Version:	RHEL-07-020210_rule
# SRG ID:	SRG-OS-000445-GPOS-00199
# Finding Level:	high
#
# Rule Summary:
#	The operating system must enable SELinux.
#
# CCI-002165 CCI-002696
#    NIST SP 800-53 Revision 4 :: AC-3 (4)
#    NIST SP 800-53 Revision 4 :: SI-6 a
#
#################################################################
{%- set stig_id = 'RHEL-07-020210' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
# Verify that the reboot system-state is acceptable
  {%- if salt.file.file_exists('/etc/selinux/config') %}
    {%- if salt.file.search('/etc/selinux/config', '^SELINUX=enforcing') %}
msg_{{ stig_id }}-modeSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Info: Current SELinux mode is Enforcing. Nothing to change.''\n"'
    - cwd: /root
    - stateful: True
    {%- else %}
      {%- if salt.file.search('/etc/selinux/config', '^SELINUX=permissive') %}
msg_{{ stig_id }}-bootSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Current SELinux mode is permissive. Setting to Enforcing for next boot.''\n"'
    - cwd: /root
    - stateful: True

sel_{{ stig_id }}-modeSet:
  selinux:
    - mode
    - name: 'Enforcing'

msg_{{ stig_id }}-chgModeSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Current SELinux mode is permissive. Changing to Enforcing.''\n"'
    - cwd: /root
    - stateful: True
      {%- elif salt.file.search('/etc/selinux/config', '^SELINUX=disabled') %}
msg_{{ stig_id }}-bootSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Current SELinux mode is disabled. Setting to Enforcing for next boot.''\n"'
    - cwd: /root
    - stateful: True
      {%- endif %}

file_{{ stig_id }}-enableSEL:
  file.replace:
    - name: '/etc/selinux/config'
    - pattern: '^SELINUX=.*'
    - repl: 'SELINUX=enforcing'
    {%- endif %}
  {%- endif %}
{%- endif %}
