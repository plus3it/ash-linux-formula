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

script_V51363-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V51363.sh

# Verify that the reboot system-state is acceptable
{% if salt['file.file_exists']('/etc/selinux/config') %}
  {% if salt['file.search']('/etc/selinux/config', '^SELINUX=enforcing') %}
msg_V51363-modeSet:
  cmd.run:
    - name: 'echo "Info: Current SELinux mode is Enforcing. Nothing to change"'
  {% else %}
    {% if salt['file.search']('/etc/selinux/config', '^SELINUX=permissive') %}
msg_V51363-bootSet:
  cmd.run:
    - name: 'echo "Current SELinux mode is permissive. Setting to Enforcing for next boot"'

sel_V51363-modeSet:
  selinux:
    - mode
    - name: 'Enforcing'

msg_V51363-chgModeSet:
  cmd.run:
    - name: 'echo "Current SELinux mode is permissive. Changing to Enforcing"'
    {% elif salt['file.search']('/etc/selinux/config', '^SELINUX=disabled') %}
msg_V51363-bootSet:
  cmd.run:
    - name: 'echo "Current SELinux mode is disabled. Setting to Enforcing for next boot"'
    {% endif %}

file_V51363-enableSEL:
  file.replace:
    - name: '/etc/selinux/config'
    - pattern: '^SELINUX=.*'
    - repl: 'SELINUX=enforcing'
  {% endif %}
{% endif %}
