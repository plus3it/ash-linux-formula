# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38605
# Finding ID:	V-38605
# Version:	RHEL-06-000224
# Finding Level:	Medium
#
#     The cron service must be running. Due to its usage for maintenance 
#     and security-supporting tasks, enabling the cron daemon is essential.
#
############################################################

script_V38605-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38605.sh

{% if salt['pkg.version']('cronie') %}
svc_V38605-crondEnabled:
  service.enabled:
  - name: 'crond'

svc_V38605-crondRunning:
  service.running:
  - name: 'crond'
{% else %}
alert_V38605-crond:
  cmd.run:
  - name: 'echo "WARNING: Cron service not installed!"'
{% endif %}

