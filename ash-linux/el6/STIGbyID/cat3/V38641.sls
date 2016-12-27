# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38641
# Finding ID:	V-38641
# Version:	RHEL-06-000262
# Finding Level:	Low
#
#     The atd service must be disabled. The "atd" service could be used by 
#     an unsophisticated insider to carry out activities outside of a 
#     normal login session, which could complicate accountability. 
#     Furthermore, the need to schedule tasks with "at" or "batch" is not 
#     common. 
#
############################################################

{%- set stigId = 'V38641' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('at') %}
svc_{{ stigId }}-atdEnabled:
  service.disabled:
    - name: 'atd'

svc_{{ stigId }}-atdRunning:
  service.dead:
    - name: 'atd'
{%- else %}
notice_{{ stigId }}-notPresent:
  cmd.run:
    - name: 'echo "The at subsystem is not installed"'
{%- endif %}
