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

{%- set stig_id = '38530' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

{%- set auditRules = '/etc/audit/audit.rules' %}
{%- set checkFile = '/etc/localtime' %}
{%- set newRule = '-w ' + checkFile + ' -p wa -k audit_time_rules' %}

{%- if not salt['cmd.shell']('grep -c -E -e "' + newRule + '" ' + auditRules , output_loglevel='quiet') == '0' %}
file_V{{ stig_id }}_auditRules:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{%- elif not salt['cmd.shell']('grep -c -E -e "' + checkFile + '" ' + auditRules , output_loglevel='quiet') == '0' %}
file_V{{ stig_id }}_auditRules:
  file.replace:
    - name: '{{ auditRules }}'
    - pattern: '{{ checkFile }}'
    - repl: '{{ newRule }}'
{%- else %}
file_V{{ stig_id }}_auditRules:
  file.append:
    - name: '{{ auditRules }}'
    - text: |

        # Monitor {{ checkFile }} for changes (per STIG-ID V-{{ stig_id }})
        {{ newRule }}
{%- endif %}
