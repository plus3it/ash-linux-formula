# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38646
# Finding ID:	V-38646
# Version:	RHEL-06-000266
# Finding Level:	Low
#
#     The oddjobd service must not be running. The "oddjobd" service may 
#     provide necessary functionality in some environments but it can be 
#     disabled if it is not needed. Execution of tasks by privileged 
#     programs, on behalf of unprivileged ones, has traditionally been a 
#     source of privilege escalation security issues. 
#
############################################################

{%- set stigId = 'V38646' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('oddjob') %}
svc_{{ stigId }}-oddjobdEnabled:
  service.disabled:
    - name: 'oddjobd'

svc_{{ stigId }}-oddjobdRunning:
  service.dead:
    - name: 'oddjobd'
{%- else %}
notice_{{ stigId }}-notPresent:
  cmd.run:
    - name: 'echo "The oddjob subsystem is not installed"'
{%- endif %}
