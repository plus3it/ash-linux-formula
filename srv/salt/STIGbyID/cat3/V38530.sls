# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38530
# Finding ID:	V-38530
# Version:	RHEL-06-000173
# Finding Level:	Low
#
#     The audit system must be configured to audit all attempts to alter 
#     system time through /etc/localtime. Arbitrary changes to the system 
#     time can be used to obfuscate nefarious activities in log files, as 
#     well as to confuse network services that are highly dependent upon an 
#     accurate system time (such as sshd). All changes to the system time 
#     should be audited. 
#
#  CCI: CCI-000169
#  NIST SP 800-53 :: AU-12 a
#  NIST SP 800-53A :: AU-12.1 (ii)
#  NIST SP 800-53 Revision 4 :: AU-12 a
#
############################################################

script_V38530-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38530.sh

{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/localtime -p wa -k audit_time_rules') %}
file_auditRules:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/localtime') %}
file_auditRules:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/localtime.*$'
  - repl: '-w /etc/localtime -p wa -k audit_time_rules'
{% else %}
file_auditRules:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/localtime for changes (per STIG-ID V-38530)'
    - '-w /etc/localtime -p wa -k audit_time_rules'
{% endif %}
