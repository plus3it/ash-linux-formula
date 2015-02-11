# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38541
# Finding ID:	V-38541
# Version:	RHEL-06-000183
# Finding Level:	Low
#
#     The audit system must be configured to audit modifications to the 
#     systems Mandatory Access Control (MAC) configuration (SELinux). The 
#     system's mandatory access policy (SELinux) should not be arbitrarily 
#     changed by anything other than administrator action. All changes to 
#     MAC policy should be audited.
#
############################################################

script_V38541-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38541.sh

# Monitoring of SELinux MAC config
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/selinux/ -p wa -k MAC-policy') %}
file_V38541-auditRules_selMAC:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/selinux/') %}
file_V38541-auditRules_selMAC:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/selinux/.*$'
  - repl: '-w /etc/selinux/ -p wa -k MAC-policy'
{% else %}
file_V38541-auditRules_selMAC:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/selinux/ for changes (per STIG-ID V-38541)'
    - '-w /etc/selinux/ -p wa -k MAC-policy'
{% endif %}

