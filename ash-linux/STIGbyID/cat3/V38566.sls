# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38566
# Finding ID:	V-38566
# Version:	RHEL-06-000197
# Finding Level:	Low
#
#     The audit system must be configured to audit failed attempts to 
#     access files and programs. Unsuccessful attempts to access files 
#     could be an indicator of malicious activity on a system. Auditing 
#     these events could serve as evidence of potential system compromise.
#
############################################################

script_V38566-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38566.sh

# Monitoring of SELinux DAC config
{% if grains['cpuarch'] == 'x86_64' %}
# ...for unprivileged users
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access') %}
file_V38566-auditRules_selEACCESusers:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', 'EACCES -F auid>=500 ') %}
file_V38566-auditRules_selEACCESusers:
  file.replace:
    - name: '/etc/audit/audit.rules'
    - pattern: '^.*EACCES -F auid>=500 .*$'
    - repl: '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access'
  {% else %}
file_V38566-auditRules_selEACCESusers:
  file.append:
    - name: '/etc/audit/audit.rules'
    - text:
      - '# Monitor for SELinux DAC changes (per STIG-ID V-38566)'
      - '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access'
  {% endif %}

  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access') %}
file_V38566-auditRules_selEPERMusers:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', 'EPERM -F auid>=500 ') %}
file_V38566-auditRules_selEPERMusers:
  file.replace:
    - name: '/etc/audit/audit.rules'
    - pattern: '^.*EPERM -F auid>=500 .*$'
    - repl: '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access'
  {% else %}
file_V38566-auditRules_selEPERMusers:
  file.append:
    - name: '/etc/audit/audit.rules'
    - text:
      - '# Monitor for SELinux DAC changes (per STIG-ID V-38566)'
      - '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access'
  {% endif %}

# ...for root user
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid=0 -k access') %}
file_V38566-auditRules_selEACCESroot:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', 'EACCES -F auid=0') %}
file_V38566-auditRules_selEACCESroot:
  file.replace:
    - name: '/etc/audit/audit.rules'
    - pattern: '^.*EACCES -F auid=0.*$'
    - repl: '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid=0 -k access'
  {% else %}
file_V38566-auditRules_selEACCESroot:
  file.append:
    - name: '/etc/audit/audit.rules'
    - text:
      - '# Monitor for SELinux DAC changes (per STIG-ID V-38566)'
      - '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid=0 -k access'
  {% endif %}

  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid=0 -k access') %}
file_V38566-auditRules_selEPERMroot:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', 'EPERM -F auid=0') %}
file_V38566-auditRules_selEPERMroot:
  file.replace:
    - name: '/etc/audit/audit.rules'
    - pattern: '^.*EPERM -F auid=0.*$'
    - repl: '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid=0 -k access'
  {% else %}
file_V38566-auditRules_selEPERMroot:
  file.append:
    - name: '/etc/audit/audit.rules'
    - text:
      - '# Monitor for SELinux DAC changes (per STIG-ID V-38566)'
      - '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid=0 -k access'
  {% endif %}
{% else %}
file_V38566-auditRules_selEACCES:
  cmd.run:
    - name: 'echo "Architecture not supported: no changes made"'
{% endif %}
