# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51363
# Finding ID:	V-51363
# Version:	RHEL-06-000020
# Finding Level:	Medium
#
#     Setting the SELinux state to enforcing ensures SELinux is able to 
#     confine potentially compromised processes to the security policy, which 
#     is designed to prevent them from causing damage to the system or 
#     further elevating their privileges. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
##############################################################################

{%- set stigId = 'V51363' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

# Verify that the reboot system-state is acceptable
{%- if salt.file.file_exists('/etc/selinux/config') %}
  {%- if salt.file.search('/etc/selinux/config', '^SELINUX=enforcing') %}
msg_{{ stigId }}-modeSet:
  cmd.run:
    - name: 'echo "Info: Current SELinux mode is Enforcing. Nothing to change"'
  {%- else %}
    {%- if salt.file.search('/etc/selinux/config', '^SELINUX=permissive') %}
msg_{{ stigId }}-bootSet:
  cmd.run:
    - name: 'echo "Current SELinux mode is permissive. Setting to Enforcing for next boot"'

sel_{{ stigId }}-modeSet:
  selinux:
    - mode
    - name: 'Enforcing'

msg_{{ stigId }}-chgModeSet:
  cmd.run:
    - name: 'echo "Current SELinux mode is permissive. Changing to Enforcing"'
    {%- elif salt.file.search('/etc/selinux/config', '^SELINUX=disabled') %}
msg_{{ stigId }}-bootSet:
  cmd.run:
    - name: 'echo "Current SELinux mode is disabled. Setting to Enforcing for next boot"'
    {%- endif %}

file_{{ stigId }}-enableSEL:
  file.replace:
    - name: '/etc/selinux/config'
    - pattern: '^SELINUX=.*'
    - repl: 'SELINUX=enforcing'
  {%- endif %}
{%- endif %}
