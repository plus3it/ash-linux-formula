# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38541
# Finding ID:	V-38541
# Version:	RHEL-06-000183
# Finding Level:	Low
#
#     The audit system must be configured to audit modifications to the
#     systems Mandatory Access Control (MAC) configuration (SELinux). The
#     system's mandatory access policy (SELinux) should not be arbitrarily
#     changed by anything other than administrator action. All changes to
#     MAC policy should be audited.
#
############################################################

{%- set stig_id = '38541' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

# Monitoring of SELinux MAC config
{%- set audit_path = '/etc/selinux/' %}
{%- set rule = '-w ' + audit_path + ' -p wa -k MAC-policy' %}
{%- set audit_cfg_file = '/etc/audit/audit.rules' %}

{%- if not salt['cmd.shell']('grep -c -E -e "' + rule + '" ' + audit_cfg_file , output_loglevel='quiet') == '0' %}
file_V{{ stig_id }}-auditRules_selMAC:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
{%- elif not salt['cmd.shell']('grep -c -E -e "' + audit_path + '" ' + audit_cfg_file , output_loglevel='quiet') == '0' %}
file_V{{ stig_id }}-auditRules_selMAC:
  file.replace:
    - name: '{{ audit_cfg_file }}'
    - pattern: '^.*{{ audit_path }}.*$'
    - repl: '{{ rule }}'
{%- else %}
file_V{{ stig_id }}-auditRules_selMAC:
  file.append:
    - name: '{{ audit_cfg_file }}'
    - text: |

        # Monitor {{ audit_path }} for changes (per STIG-ID V-{{ stig_id }})
        {{ rule }}
{%- endif %}
