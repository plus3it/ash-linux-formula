# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38534
# Finding ID:	V-38534
# Version:	RHEL-06-000175
# Finding Level:	Low
#
#     The operating system must automatically audit account modification. 
#     In addition to auditing new user and group accounts, these watches 
#     will alert the system administrator(s) to any modifications. Any 
#     unexpected users, groups, or modifications should be investigated
#     for legitimacy
#
#  CCI: CCI-001403
#  NIST SP 800-53 :: AC-2 (4)
#  NIST SP 800-53A :: AC-2 (4).1 (i&ii)
#  NIST SP 800-53 Revision 4 :: AC-2 (4)
#
############################################################

script_V38534-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38534.sh

# Monitoring of /etc/group file
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/group -p wa -k audit_account_changes') %}
file_V38534-auditRules_group:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/group') %}
file_V38534-auditRules_group:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/group.*$'
  - repl: '-w /etc/group -p wa -k audit_account_changes'
{% else %}
file_V38534-auditRules_group:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/group for changes (per STIG-ID V-38534)'
    - '-w /etc/group -p wa -k audit_account_changes'
{% endif %}

# Monitoring of /etc/passwd file
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/passwd -p wa -k audit_account_changes') %}
file_V38534-auditRules_passwd:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/passwd') %}
file_V38534-auditRules_passwd:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/passwd.*$'
  - repl: '-w /etc/passwd -p wa -k audit_account_changes'
{% else %}
file_V38534-auditRules_passwd:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/passwd for changes (per STIG-ID V-38534)'
    - '-w /etc/passwd -p wa -k audit_account_changes'
{% endif %}

# Monitoring of /etc/gshadow file
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/gshadow -p wa -k audit_account_changes') %}
file_V38534-auditRules_gshadow:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/gshadow') %}
file_V38534-auditRules_gshadow:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/gshadow.*$'
  - repl: '-w /etc/gshadow -p wa -k audit_account_changes'
{% else %}
file_V38534-auditRules_gshadow:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/gshadow for changes (per STIG-ID V-38534)'
    - '-w /etc/gshadow -p wa -k audit_account_changes'
{% endif %}

# Monitoring of /etc/shadow file
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/shadow -p wa -k audit_account_changes') %}
file_V38534-auditRules_shadow:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/shadow') %}
file_V38534-auditRules_shadow:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/shadow.*$'
  - repl: '-w /etc/shadow -p wa -k audit_account_changes'
{% else %}
file_V38534-auditRules_shadow:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/shadow for changes (per STIG-ID V-38534)'
    - '-w /etc/shadow -p wa -k audit_account_changes'
{% endif %}

# Monitoring of /etc/security/opasswd file
{% if salt['file.search']('/etc/audit/audit.rules', '-w /etc/security/opasswd -p wa -k audit_account_changes') %}
file_V38534-auditRules_opasswd:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
{% elif salt['file.search']('/etc/audit/audit.rules', '/etc/security/opasswd') %}
file_V38534-auditRules_opasswd:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*/etc/security/opasswd.*$'
  - repl: '-w /etc/security/opasswd -p wa -k audit_account_changes'
{% else %}
file_V38534-auditRules_opasswd:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Monitor /etc/security/opasswd for changes (per STIG-ID V-38534)'
    - '-w /etc/security/opasswd -p wa -k audit_account_changes'
{% endif %}
