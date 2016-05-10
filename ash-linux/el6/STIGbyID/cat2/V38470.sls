# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38470
# Finding ID:	V-38470
# Version:	RHEL-06-000005
# Finding Level:	Medium
#
#     The audit system must alert designated staff members when the audit 
#     storage volume approaches capacity. Notifying administrators of an 
#     impending disk space problem may allow them to take corrective action 
#     prior to any disruption.
#
#  CCI: CCI-000138
#  NIST SP 800-53 :: AU-4
#  NIST SP 800-53A :: AU-4.1 (ii)
#
############################################################

{%- set stigId = 'V38470' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/audit/auditd.conf' %}
{%- set parmName = 'space_left_action' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

file_{{ stigId }}:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: "^{{ parmName }} =.*"
    - repl: "{{ parmName }} = email"
