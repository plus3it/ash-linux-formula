# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38568
# Finding ID:	V-38568
# Version:	RHEL-06-000199
# Finding Level:	Low
#
#     The audit system must be configured to audit successful file system 
#     mounts. The unauthorized exportation of data to external media could 
#     result in an information leak where classified information, Privacy 
#     Act information, and intellectual property could be lost. An audit 
#     trail should be created each time a filesystem is mounted to help 
#     identify and guard against information loss
#
############################################################

script_V38568-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38568.sh

# Monitoring of SELinux DAC config
{% if grains['cpuarch'] == 'x86_64' %}
# ...for unprivileged users
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export') %}
file_V38568-auditRules_selDACusers:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', ' mount -F auid>=500 ') %}
file_V38568-auditRules_selDACusers:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.* mount -F auid>=500 .*$'
  - repl: '-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export'
  {% else %}
file_V38568-auditRules_selDACusers:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor for SELinux DAC changes (per STIG-ID V-38568)'
    - '-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export'
  {% endif %}

# ...for root user
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S mount -F auid=0 -k export') %}
file_V38568-auditRules_selDACroot:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', ' mount .*auid=0 ') %}
file_V38568-auditRules_selDACroot:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.* mount .*auid=0 .*$'
  - repl: '-a always,exit -F arch=b64 -S mount -F auid=0 -k export'
  {% else %}
file_V38568-auditRules_selDACroot:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor for SELinux DAC changes (per STIG-ID V-38568)'
    - '-a always,exit -F arch=b64 -S mount -F auid=0 -k export'
  {% endif %}
{% else %}
file_V38568-auditRules_selDAC:
  cmd.run:
  - name: 'echo "Architecture not supported: no changes made"'
{% endif %}

