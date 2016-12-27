# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38644
# Finding ID:	V-38644
# Version:	RHEL-06-000265
# Finding Level:	Low
#
#     The ntpdate service must not be running. The "ntpdate" service may 
#     only be suitable for systems which are rebooted frequently enough 
#     that clock drift does not cause problems between reboots. In any 
#     event, the functionality of the ntpdate service is now available in 
#     the ntpd program and should be considered deprecated. 
#
############################################################

{%- set stigId = 'V38644' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('ntpdate') %}
svc_{{ stigId }}-ntpdateEnabled:
  service.disabled:
    - name: 'ntpdate'

svc_{{ stigId }}-ntpdateRunning:
  service.dead:
    - name: 'ntpdate'
{%- else %}
notice_{{ stigId }}-notPresent:
  cmd.run:
    - name: 'echo "The ntpdate subsystem is not installed"'
{%- endif %}
