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

script_V38605-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38605.sh
    - cwd: '/root'

{%- if not salt['pkg.version']('cronie') %}
pkg_V38605-cronie:
  pkg.installed:
    - name: 'cronie'
{%- endif %}

svc_V38605-crondEnabled:
  service.enabled:
    - name: 'crond'

svc_V38605-crondRunning:
  service.running:
    - name: 'crond'
