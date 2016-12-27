# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38680
# Finding ID:	V-38680
# Version:	RHEL-06-000313
# Finding Level:	Medium
#
#     The audit system must identify staff members to receive notifications 
#     of audit log storage volume capacity issues. Email sent to the root 
#     account is typically aliased to the administrators of the system, who 
#     can take appropriate action.
#
#  CCI: CCI-000139
#  NIST SP 800-53 :: AU-5 a
#  NIST SP 800-53A :: AU-5.1 (ii)
#  NIST SP 800-53 Revision 4 :: AU-5 a
#
############################################################

{%- set stigId = 'V38680' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/audit/auditd.conf' %}
{%- set checkPtn = 'action_mail_acct' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.file_exists(checkFile) %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^{{ checkPtn }}.*$'
    - repl: '{{ checkPtn }} = root'
{%- else %}
warn_{{ stigId }}:
  cmd.run:
    - name: 'echo "The audit config file ({{ checkFile }}) does not exist"'
{%- endif %}
