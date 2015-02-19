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

{% set stig_id = '38536' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V{{ stig_id }}.sh

{% set auditCfg = '/etc/audit/audit.rules' %}
{% set audit_options = '-p wa -k audit_account_changes' %}

{% set files = [
    '/etc/group',
    '/etc/passwd',
    '/etc/security/opasswd',
    '/etc/shadow',
    '/etc/gshadow',
] %}

{% for file in files %}
  {% set rule = '-w ' + file + ' ' + audit_options %}
  {% if not salt['cmd.run']('grep -c -E -e "' + rule + '" ' + auditCfg ) == '0' %}
file_V{{ stig_id }}-auditRules_{{ file }}:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
  {% elif not salt['cmd.run']('grep -c -E -e "' + file + '" ' + auditCfg ) == '0' %}
file_V{{ stig_id }}-auditRules_{{ file }}:
  file.replace:
    - name: '{{ auditCfg }}'
    - pattern: '^.*{{ file }}.*$'
    - repl: '{{ rule }}'
  {% else %}
file_V{{ stig_id }}-auditRules_{{ file }}:
  file.append:
    - name: '{{ auditCfg }}'
    - text: |
        
        # Monitor {{ file }} for changes (per STIG-ID V-{{ stig_id }})
        {{ rule }}
  {% endif %}
{% endfor %}
