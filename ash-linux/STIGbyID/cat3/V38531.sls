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

{% set stig_id = '38531' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V{{ stig_id }}.sh
    - cwd: /root

{% set ruleFile = '/etc/audit/audit.rules' %}
{% set auditRule = '-p wa -k audit_account_changes' %}
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
{% if not salt['cmd.run']('grep -c -E -e "' + groupRule + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_group:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif not salt['cmd.run']('grep -c -E -e "' + groupFile + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_group:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ groupFile }}.*$'
    - repl: '{{ groupRule }}'
{% else %}
file_{{ stig_id }}-auditRules_group:
  file.append:
    - name: '{{ ruleFile }}'
    - text: |
        
        # Monitor {{ groupFile }} for changes (per STIG-ID V-{{ stig_id }})
        {{ groupRule }}
{% endif %}

# Monitoring of /etc/passwd file
{% if not salt['cmd.run']('grep -c -E -e "' + passwdRule + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_passwd:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif not salt['cmd.run']('grep -c -E -e "' + passwdFile + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_passwd:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ passwdFile }}.*$'
    - repl: '{{ passwdRule }}'
{% else %}
file_{{ stig_id }}-auditRules_passwd:
  file.append:
    - name: '{{ ruleFile }}'
    - text: |
        
        # Monitor {{ passwdFile }} for changes (per STIG-ID V-{{ stig_id }})
        {{ passwdRule }}
{% endif %}

# Monitoring of /etc/gshadow file
{% if not salt['cmd.run']('grep -c -E -e "' + gshadowRule + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_gshadow:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif not salt['cmd.run']('grep -c -E -e "' + gshadowFile + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_gshadow:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ gshadowFile }}.*$'
    - repl: '{{ gshadowRule }}'
{% else %}
file_{{ stig_id }}-auditRules_gshadow:
  file.append:
    - name: '{{ ruleFile }}'
    - text: |
        
        # Monitor {{ gshadowFile }} for changes (per STIG-ID V-{{ stig_id }})
        {{ gshadowRule }}
{% endif %}

# Monitoring of /etc/shadow file
{% if not salt['cmd.run']('grep -c -E -e "' + shadowRule + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_shadow:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif not salt['cmd.run']('grep -c -E -e "' + shadowFile + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_shadow:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ shadowFile }}.*$'
    - repl: '{{ shadowRule }}'
{% else %}
file_{{ stig_id }}-auditRules_shadow:
  file.append:
    - name: '{{ ruleFile }}'
    - text: |
        
        # Monitor {{ shadowFile }} for changes (per STIG-ID V-{{ stig_id }})
        {{ shadowRule }}
{% endif %}

# Monitoring of /etc/security/opasswd file
{% if not salt['cmd.run']('grep -c -E -e "' + opasswdRule + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_opasswd:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{% elif not salt['cmd.run']('grep -c -E -e "' + opasswdFile + '" ' + ruleFile ) == '0' %}
file_{{ stig_id }}-auditRules_opasswd:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ opasswdFile }}.*$'
    - repl: '{{ opasswdRule }}'
{% else %}
file_{{ stig_id }}-auditRules_opasswd:
  file.append:
    - name: '{{ ruleFile }}'
    - text: |
        
        # Monitor {{ opasswdFile }} for changes (per STIG-ID V-{{ stig_id }})
        {{ opasswdRule }}
{% endif %}
