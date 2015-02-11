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

script_V38618-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38618.sh

{% if salt['pkg.version']('avahi') %}
svc_V38618-avahiDisabled:
  service.disabled:
  - name: 'avahi-daemon'

svc_V38618-avahiRunning:
 service.dead:
  - name: 'avahi-daemon'

{% else %}
notice_V38618-notPresent:
   cmd.run:
   - name: 'echo "The avahi subsystem is not installed"'
{% endif %}
