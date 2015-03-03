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

script_V38646-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38646.sh
    - cwd: /root

{% if salt['pkg.version']('oddjob') %}
svc_V38646-oddjobdEnabled:
  service.disabled:
    - name: 'oddjobd'

svc_V38646-oddjobdRunning:
  service.dead:
    - name: 'oddjobd'
{% else %}
notice_V38646-notPresent:
  cmd.run:
    - name: 'echo "The oddjob subsystem is not installed"'
{% endif %}
