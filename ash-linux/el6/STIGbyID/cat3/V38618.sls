# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38618
# Finding ID:	V-38618
# Version:	RHEL-06-000246
# Finding Level:	Low
#
#     The avahi service must be disabled. Because the Avahi daemon service 
#     keeps an open network port, it is subject to network attacks. Its 
#     functionality is convenient but is only appropriate if the local 
#     network can be trusted.
#
############################################################

{%- set stigId = 'V38618' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('avahi') %}
svc_{{ stigId }}-avahiDisabled:
  service.disabled:
    - name: 'avahi-daemon'

svc_{{ stigId }}-avahiRunning:
  service.dead:
    - name: 'avahi-daemon'

{%- else %}
notice_{{ stigId }}-notPresent:
  cmd.run:
    - name: 'echo "The avahi subsystem is not installed"'
{%- endif %}
