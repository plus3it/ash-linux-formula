# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38536
# Finding ID:	V-38536
# Version:	RHEL-06-000176
# Finding Level:	Low
#
#     The operating system must automatically audit account disabling 
#     actions. In addition to auditing new user and group accounts, these 
#     watches will alert the system administrator(s) to any modifications. 
#     Any unexpected users, groups, or modifications should be investigated 
#     for legitimacy.
#
#  CCI: CCI-001404
#  NIST SP 800-53 :: AC-2 (4)
#  NIST SP 800-53A :: AC-2 (4).1 (i&ii)
#  NIST SP 800-53 Revision 4 :: AC-2 (4)
#
############################################################

script_V38536-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38536.sh

{% set auditCfg = '/etc/audit/audit.rules' %}
{% set groupFile = '/etc/group' %}
{% set groupRule = '-w ' + groupFile + ' -p wa -k audit_account_changes' %}
{% set passwdFile = '/etc/passwd' %}
{% set passwdRule = '-w ' + passwdFile + ' -p wa -k audit_account_changes' %}
{% set opasswdFile = '/etc/security/opasswd' %}
{% set opasswdRule = '-w ' + opasswdFile + ' -p wa -k audit_account_changes' %}
{% set shadowFile = '/etc/shadow' %}
{% set shadowRule = '-w ' + shadowFile + ' -p wa -k audit_account_changes' %}
{% set gshadowFile = '/etc/gshadow' %}
{% set gshadowRule = '-w ' + gshadowFile + ' -p wa -k audit_account_changes' %}

# Monitoring of /etc/group file
{% if salt['file.search'](auditCfg, groupRule) %}
file_V38536-auditRules_group:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](auditCfg, groupFile) %}
file_V38536-auditRules_group:
  file.replace:
    - name: '{{ auditCfg }}'
    - pattern: '^.*{{ groupFile }}.*$'
    - repl: '{{ groupRule }}'
{% else %}
file_V38536-auditRules_group:
  file.append:
    - name: '{{ auditCfg }}'
    - text:
      - '# Monitor {{ groupFile }} for changes (per STIG-ID V-38536)'
      - '{{ groupRule }}'
{% endif %}

# Monitoring of /etc/passwd file
{% if salt['file.search'](auditCfg, passwdRule) %}
file_V38536-auditRules_passwd:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](auditCfg, passwdFile) %}
file_V38536-auditRules_passwd:
  file.replace:
    - name: '{{ auditCfg }}'
    - pattern: '^.*{{ passwdFile }}.*$'
    - repl: '{{ passwdRule }}'
{% else %}
file_V38536-auditRules_passwd:
  file.append:
    - name: '{{ auditCfg }}'
    - text:
      - '# Monitor {{ passwdFile }} for changes (per STIG-ID V-38536)'
      - '{{ passwdRule }}'
{% endif %}

# Monitoring of /etc/gshadow file
{% if salt['file.search'](auditCfg, gshadowRule) %}
file_V38536-auditRules_gshadow:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](auditCfg, gshadowFile) %}
file_V38536-auditRules_gshadow:
  file.replace:
    - name: '{{ auditCfg }}'
    - pattern: '^.*{{ gshadow }}.*$'
    - repl: '{{ gshadowRule }}'
{% else %}
file_V38536-auditRules_gshadow:
  file.append:
    - name: '{{ auditCfg }}'
    - text:
      - '# Monitor {{ gshadowFile }} for changes (per STIG-ID V-38536)'
      - '{{ gshadowRule }}'
{% endif %}

# Monitoring of /etc/shadow file
{% if salt['file.search'](auditCfg, shadowRule) %}
file_V38536-auditRules_shadow:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](auditCfg, shadowFile) %}
file_V38536-auditRules_shadow:
  file.replace:
    - name: '{{ auditCfg }}'
    - pattern: '^.*{{ shadowFile }}.*$'
    - repl: '{{ shadowRule }}'
{% else %}
file_V38536-auditRules_shadow:
  file.append:
    - name: '{{ auditCfg }}'
    - text:
      - '# Monitor {{ shadowFile }} for changes (per STIG-ID V-38536)'
      - '{{ shadowRule }}'
{% endif %}

# Monitoring of /etc/security/opasswd file
{% if salt['file.search'](auditCfg, opasswdRule) %}
file_V38536-auditRules_opasswd:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search'](auditCfg, opasswdFile) %}
file_V38536-auditRules_opasswd:
  file.replace:
    - name: '{{ auditCfg }}'
    - pattern: '^.*{{ opasswd }}.*$'
    - repl: '{{ opasswdRule }}'
{% else %}
file_V38536-auditRules_opasswd:
  file.append:
    - name: '{{ auditCfg }}'
    - text:
      - '# Monitor {{ opasswdFile }} for changes (per STIG-ID V-38536)'
      - '{{ opasswdRule }}'
{% endif %}
