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

script_V38641-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38641.sh

{% if salt['pkg.version']('at') %}
svc_V38641-atdEnabled:
  service.disabled:
    - name: 'atd'

svc_V38641-atdRunning:
  service.dead:
    - name: 'atd'
{% else %}
notice_V38641-notPresent:
  cmd.run:
    - name: 'echo "The at subsystem is not installed"'
{% endif %}
