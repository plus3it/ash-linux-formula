# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38468
# Finding ID:	V-38468
# Version:	RHEL-06-000510
# Finding Level:	Medium
#
#     The audit system must take appropriate action when the audit storage 
#     volume is full. Taking appropriate action in case of a filled audit 
#     storage volume will minimize the possibility of losing audit records.
#
#  CCI: CCI-000140
#  NIST SP 800-53 :: AU-5 b
#  NIST SP 800-53A :: AU-5.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-5 b
#
############################################################

{%- set stigId = 'V38468' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/audit/auditd.conf' %}
{%- set parmName = 'disk_full_action' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

file_{{ stigId }}:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: "^{{ parmName }} =.*"
    - repl: "{{ parmName }} = HALT"
