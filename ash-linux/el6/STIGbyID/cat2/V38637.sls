# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38637
# Finding ID:	V-38637
# Version:	RHEL-06-000281
# Finding Level:	Medium
#
#     The system package management tool must verify contents of all files 
#     associated with the audit package. The hash on important files like 
#     audit system executables should match the information given by the 
#     RPM database. Audit executables with erroneous hashes could be a sign 
#     of nefarious activity on the ...
#
############################################################

{%- set stigId = 'V38637' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

script_{{ stigId }}-tamperCheck:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}-helper.sh
    - cwd: '/root'
