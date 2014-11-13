# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38575
# Finding ID:	V-38575
# Version:	RHEL-06-000200
# Finding Level:	Low
#
#     The audit system must be configured to audit user deletions of files 
#     and programs. Auditing file deletions will create an audit trail for 
#     files that are removed from the system. The audit trail could aid in 
#     system troubleshooting, as well as detecting malicious processes that 
#     that attempt to delete log files to conceal their presence. 
#
#  CCI: CCI-000172
#  NIST SP 800-53 :: AU-12 c
#  NIST SP 800-53A :: AU-12.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-12 c
#
############################################################

script_V38575-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38575.sh

# Monitoring of SELinux DAC config
{% if grains['cpuarch'] == 'x86_64' %}
# ...for unprivileged users
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete') %}
file_V38575-auditRules_selusers:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete') %}
file_V38575-auditRules_selusers:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*arch=b64.*unlink.*auid>=500.*$'
  - repl: '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete'
  {% else %}
file_V38575-auditRules_selusers:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor for SELinux DAC changes (per STIG-ID V-38575)'
    - '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete'
  {% endif %}

# ...for root user
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete') %}
file_V38575-auditRules_selroot:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete') %}
file_V38575-auditRules_selroot:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*arch=b64.*unlink.*auid=0.*$'
  - repl: '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete'
  {% else %}
file_V38575-auditRules_selroot:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor for SELinux DAC changes (per STIG-ID V-38575)'
    - '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete'
  {% endif %}
{% else %}
file_V38575-auditRules_sel:
  cmd.run:
  - name: 'echo "Architecture not supported: no changes made"'
{% endif %}

