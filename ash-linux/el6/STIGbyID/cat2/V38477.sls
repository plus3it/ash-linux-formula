# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38477
# Finding ID:	V-38477
# Version:	RHEL-06-000051
# Finding Level:	Medium
#
#     Users must not be able to change passwords more than once every 24 
#     hours. Setting the minimum password age protects against users 
#     cycling back to a favorite password after satisfying the password 
#     reuse requirement.
#
# CCI: CCI-000198
# NIST SP 800-53 :: IA-5 (1) (d)
# NIST SP 800-53A :: IA-5 (1).1 (v)
# NIST SP 800-53 Revision 4 :: IA-5 (1) (d)
#
############################################################

{%- set stigId = 'V38477' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/login.defs' %}
{%- set parmName = 'PASS_MIN_DAYS' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

file_{{ stigId }}:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: "^{{ parmName }}.*$"
    - repl: "{{ parmName }}	1"
