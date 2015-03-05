# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38538
# Finding ID:	V-38538
# Version:	RHEL-06-000177
# Finding Level:	Low
#
#     The operating system must automatically audit account termination. In 
#     addition to auditing new user and group accounts, these watches will 
#     alert the system administrator(s) to any modifications. Any 
#     unexpected users, groups, or modifications should be investigated 
#     for legitimacy.
#
############################################################

{%- set stig_id = 'V38538' %}
{%- set helperLoc = 'ash-linux/STIGbyID/cat3/files' %}
{%- set audRulCfg = '/etc/audit/audit.rules' %}
{%- set auditRule = '-p wa -k audit_account_changes' %}
{%- set checkFiles = [
  '/etc/passwd',
  '/etc/group',
  '/etc/shadow',
  '/etc/gshadow',
  '/etc/security/opasswd',
] %}

# Output a action description
script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Iterate each file in {{ checkFiles }}
{%- for checkFile in checkFiles %}
  {%- set fullRule = '-w' + ' ' + checkFile + ' ' + auditRule %}

  # If the rule already exists in the file, verbatim:
  # Do nothing but call out that fact
  {%- if not salt['cmd.run']('grep -c -E -e "' + fullRule + '" ' + audRulCfg ) == '0' %}

rule_{{ stig_id }}-{{ checkFile }}:
  cmd.run:
    - name: 'echo "STIG-specified audit rule already in place"'

  # If it doesn't exist, add it (with a comment)
  {%- else %}

rule_{{ stig_id }}-{{ checkFile }}:
  file.append:
    - name: '{{ audRulCfg }}'
    - text: |

        # Monitor {{ checkFile }} for changes (per STIG-ID {{ stig_id }})
        {{ fullRule }}

  # End our main logic-branching
  {%- endif %}

# End iteration of file list
{%- endfor %}
