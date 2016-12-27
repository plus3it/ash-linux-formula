# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38605
# Finding ID:	V-38605
# Version:	RHEL-06-000224
# Finding Level:	Medium
#
#     The cron service must be running. Due to its usage for maintenance 
#     and security-supporting tasks, enabling the cron daemon is essential.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38605' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if not salt.pkg.version('cronie') %}
pkg_{{ stigId }}-cronie:
  pkg.installed:
    - name: 'cronie'
{%- endif %}

svc_{{ stigId }}-crondEnabled:
  service.enabled:
    - name: 'crond'

svc_{{ stigId }}-crondRunning:
  service.running:
    - name: 'crond'
