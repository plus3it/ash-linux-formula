# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38479
# Finding ID:	V-38479
# Version:	RHEL-06-000053
# Finding Level:	Medium
#
#     User passwords must be changed at least every 60 days. Setting the 
#     password maximum age ensures users are required to periodically 
#     change their passwords. This could possibly decrease the utility of a 
#     stolen password. Requiring shorter password lifetimes ...
#
#  CCI: CCI-000199
#  NIST SP 800-53 :: IA-5 (1) (d)
#  NIST SP 800-53A :: IA-5 (1).1 (v)
#  NIST SP 800-53 Revision 4 :: IA-5 (1) (d)
#
############################################################

{%- set stigId = 'V38479' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/login.defs' %}
{%- set parmName = 'PASS_MAX_DAYS' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

file_{{ stigId }}:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: "^{{ parmName }}.*$"
    - repl: "{{ parmName }}	60"
