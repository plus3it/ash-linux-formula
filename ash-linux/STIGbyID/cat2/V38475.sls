# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38475
# Finding ID:	V-38475
# Version:	RHEL-06-000050
# Finding Level:	Medium
#
#     The system must require passwords to contain a minimum of 14 
#     characters. Requiring a minimum password length makes password 
#     cracking attacks more difficult by ensuring a larger search space. 
#     However, any security benefit from an onerous requirement must be 
#     carefully ...
#
#  CCI: CCI-000205
#  NIST SP 800-53 :: IA-5 (1) (a)
#  NIST SP 800-53A :: IA-5 (1).1 (i)
#  NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
#
############################################################

{%- set stigId = 'V38475' %}
{%- set helperLoc = 'ash-linux/STIGbyID/cat2' %}
{%- set chkFile = '/etc/login.defs' %}
{%- set parmName = 'PASS_MIN_LEN' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

file_{{ stigId }}:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: "^{{ parmName }}.*$"
    - repl: "{{ parmName }}	14"
