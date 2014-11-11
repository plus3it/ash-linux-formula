# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38557
# Finding ID:	V-38557
# Version:	RHEL-06-000191
# Finding Level:	Low
#
#     The audit system must be configured to audit all discretionary access 
#     control permission modifications using fsetxattr. The changing of 
#     file permissions could indicate that a user is attempting to gain 
#     access to information that would otherwise be disallowed. Auditing 
#     DAC modifications can facilitate the identification of patterns of 
#     abuse among both authorized and unauthorized users.
# 
#  CCI: CCI-000172
#  NIST SP 800-53 :: AU-12 c
#  NIST SP 800-53A :: AU-12.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-12 c
#
############################################################

script_V38557-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38557.sh

# Monitoring of SELinux DAC config
{% if grains['cpuarch'] == 'x86_64' %}
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod -a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod') %}
file_V38557-auditRules_selDAC:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', ' fsetxattr ') %}
file_V38557-auditRules_selDAC:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.* fsetxattr .*$'
  - repl: '-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod -a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod'
  {% else %}
file_V38557-auditRules_selDAC:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor for SELinux DAC changes (per STIG-ID V-38557)'
    - '-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod -a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod'
  {% endif %}
{% else %}
file_V38557-auditRules_selDAC:
  cmd.run:
  - name: 'echo "Architecture not supported: no changes made"'
{% endif %}

