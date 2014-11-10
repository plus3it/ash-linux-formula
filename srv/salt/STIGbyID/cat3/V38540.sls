# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38540
# Finding ID:	V-38540
# Version:	RHEL-06-000182
# Finding Level:	Low
#
#     The audit system must be configured to audit modifications to the 
#     systems network configuration. The network environment should not be 
#     modified by anything other than administrator action. Any change to 
#     network parameters should be audited.
#
############################################################

script_V38540-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38540.sh

# Monitoring of /etc/issue file
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/issue -p wa -k audit_network_modifications') %}
file_V38540-auditRules_issue:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/issue') %}
file_V38540-auditRules_issue:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/issue.*$'
  - repl: '-w /etc/issue -p wa -k audit_network_modifications'
{% else %}
file_V38540-auditRules_issue:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/issue for changes (per STIG-ID V-38540)'
    - '-w /etc/issue -p wa -k audit_network_modifications'
{% endif %}

# Monitoring of /etc/issue.net file
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/issue.net -p wa -k audit_network_modifications') %}
file_V38540-auditRules_issueNet:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/issue.net') %}
file_V38540-auditRules_issueNet:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/issue.net.*$'
  - repl: '-w /etc/issue.net -p wa -k audit_network_modifications'
{% else %}
file_V38540-auditRules_issueNet:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/issue.net for changes (per STIG-ID V-38540)'
    - '-w /etc/issue.net -p wa -k audit_network_modifications'
{% endif %}

# Monitoring of /etc/hosts file
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/hosts -p wa -k audit_network_modifications') %}
file_V38540-auditRules_hosts:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/hosts') %}
file_V38540-auditRules_hosts:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/hosts.*$'
  - repl: '-w /etc/hosts -p wa -k audit_network_modifications'
{% else %}
file_V38540-auditRules_hosts:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/hosts for changes (per STIG-ID V-38540)'
    - '-w /etc/hosts -p wa -k audit_network_modifications'
{% endif %}

# Monitoring of /etc/sysconfig/network file
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/sysconfig/network -p wa -k audit_network_modifications') %}
file_V38540-auditRules_sysconfigNetwork:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/sysconfig/network') %}
file_V38540-auditRules_sysconfigNetwork:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/sysconfig/network.*$'
  - repl: '-w /etc/sysconfig/network -p wa -k audit_network_modifications'
{% else %}
file_V38540-auditRules_sysconfigNetwork:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/sysconfig/network for changes (per STIG-ID V-38540)'
    - '-w /etc/sysconfig/network -p wa -k audit_network_modifications'
{% endif %}

{% if grains['cpuarch'] == 'x86_64' %}
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications') %}
file_V38522-settimeofday:
  cmd.run:
  - name: 'echo "Appropriate audit-rule already present"'
  {% else %}
file_V38522-settimeofday:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Audit all network configuration modifications (per STIG-ID V-38540)'
    - '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications'
  {% endif %}
{% else %}
file_V38522-settimeofday:
  cmd.run:
  - name: 'echo "Architecture not supported: no changes made"'
{% endif %}
