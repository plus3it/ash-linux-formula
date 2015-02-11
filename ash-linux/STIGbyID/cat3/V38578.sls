# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38578
# Finding ID:	V-38578
# Version:	RHEL-06-000201
# Finding Level:	Low
#
#     The audit system must be configured to audit changes to the 
#     /etc/sudoers file. The actions taken by system administrators should 
#     be audited to keep a record of what was executed on the system, as 
#     well as, for accountability purposes.
#
#  CCI: CCI-000172
#  NIST SP 800-53 :: AU-12 c
#  NIST SP 800-53A :: AU-12.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-12 c
#
############################################################

script_V38578-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38578.sh

{% set ruleFile = '/etc/audit/audit.rules' %}
{% set checkFile = '/etc/sudoers' %}
{% set auditRule = '-w ' + checkFile + ' -p wa -k actions' %}

# Monitoring of /etc/sudoers file
{% if salt['file.search'](ruleFile, auditRule) %}
file_V38578-auditRules_sudoers:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](ruleFile, checkFile) %}
file_V38578-auditRules_sudoers:
  file.replace:
  - name: '{{ ruleFile }}'
  - pattern: '^.*{{ checkFile }}.*$'
  - repl: '{{ auditRule }}'
{% else %}
file_V38578-auditRules_sudoers:
  file.append:
  - name: '{{ ruleFile }}'
  - text:
    - '# Monitor {{ checkFile }} for changes (per STIG-ID V-38578)'
    - '{{ auditRule }}'
{% endif %}
