# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38531
# Finding ID:	V-38531
# Version:	RHEL-06-000174
# Finding Level:	Low
#
#     The operating system must automatically audit account creation. In 
#     addition to auditing new user and group accounts, these watches will 
#     alert the system administrator(s) to any modifications. Any 
#     unexpected users, groups, or modifications should be investigated for 
#     legitimacy.
#
#  CCI: CCI-000018
#  NIST SP 800-53 :: AC-2 (4)
#  NIST SP 800-53A :: AC-2 (4).1 (i&ii)
#  NIST SP 800-53 Revision 4 :: AC-2 (4)
#
############################################################

script_V38531-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38531.sh

{% set ruleFile = '/etc/audit/audit.rules' %}
{% set auditRule = ' -p wa -k audit_account_changes' %}
{% set groupFile = '/etc/group' %}
{% set groupRule = '-w ' + groupFile + auditRule %}
{% set passwdFile= '/etc/passwd' %}
{% set passwdRule = '-w ' + passwdFile + auditRule %}
{% set opasswdFile = '/etc/security/opasswd' %}
{% set opasswdRule = '-w ' + opasswdFile + auditRule %}
{% set shadowFile = '/etc/shadow' %}
{% set shadowRule = '-w ' + shadowFile + auditRule %}
{% set gshadowFile= '/etc/gshadow' %}
{% set gshadowRule = '-w ' + gshadowFile + auditRule %}

# Monitoring of /etc/group file
{% if salt['file.search'](ruleFile, groupRule) %}
file_V38531-auditRules_group:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](ruleFile, groupFile) %}
file_V38531-auditRules_group:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*' + groupFile '.*$'
    - repl: '{{ groupRule }}'
{% else %}
file_V38531-auditRules_group:
  file.append:
    - name: '{{ ruleFile }}'
    - text:
      - '# Monitor {{ groupFile }} for changes (per STIG-ID V-38531)'
      - '{{ groupRule }}'
{% endif %}

# Monitoring of /etc/passwd file
{% if salt['file.search'](ruleFile, passwdRule) %}
file_V38531-auditRules_passwd:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](ruleFile, passwdFile) %}
file_V38531-auditRules_passwd:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ passwdFile }}.*$'
    - repl: '{{ passwdRule }}'
{% else %}
file_V38531-auditRules_passwd:
  file.append:
    - name: '{{ ruleFile }}'
    - text:
      - '# Monitor {{ passwdFile }} for changes (per STIG-ID V-38531)'
      - '{{ passwdRule }}'
{% endif %}

# Monitoring of /etc/gshadow file
{% if salt['file.search'](ruleFile, gshadowRule) %}
file_V38531-auditRules_gshadow:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](ruleFile, gshadowFile) %}
file_V38531-auditRules_gshadow:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ gshadowFile }}.*$'
    - repl: '{{ gshadowRule }}'
{% else %}
file_V38531-auditRules_gshadow:
  file.append:
    - name: '{{ ruleFile }}'
    - text:
      - '# Monitor {{ gshadowFile }} for changes (per STIG-ID V-38531)'
      - '{{ gshadowRule }}'
{% endif %}

# Monitoring of /etc/shadow file
{% if salt['file.search'](ruleFile, shadowRule) %}
file_V38531-auditRules_shadow:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](ruleFile, shadowFile) %}
file_V38531-auditRules_shadow:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ shadowFile }}.*$'
    - repl: '{{ shadowRule }}'
{% else %}
file_V38531-auditRules_shadow:
  file.append:
    - name: '{{ ruleFile }}'
    - text:
      - '# Monitor {{ shadowFile }} for changes (per STIG-ID V-38531)'
      - '{{ shadowRule }}'
{% endif %}

# Monitoring of /etc/security/opasswd file
{% if salt['file.search'](ruleFile, opasswdRule) %}
file_V38531-auditRules_opasswd:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](ruleFile, opasswdFile) %}
file_V38531-auditRules_opasswd:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ opasswdFile }}.*$'
    - repl: '{{ opasswdRule }}'
{% else %}
file_V38531-auditRules_opasswd:
  file.append:
    - name: '{{ ruleFile }}'
    - text:
      - '# Monitor {{ opasswdFile }} for changes (per STIG-ID V-38531)'
      - '{{ opasswdRule }}'
{% endif %}
