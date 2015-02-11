# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38584
# Finding ID:	V-38584
# Version:	RHEL-06-000204
# Finding Level:	Low
#
#     The xinetd service must be uninstalled if no network services 
#     utilizing it are enabled. Removing the "xinetd" package decreases the 
#     risk of the xinetd service's accidental (or intentional) activation.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

script_V38584-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38584.sh

{% if salt['pkg.version']('xinetd') %}
svc_V38584-xinetdEnabled:
  service.disabled:
    - name: 'xinetd'

svc_V38584-xinetdRunning:
  service.dead:
    - name: 'xinetd'

pkg_V38584-remove:
  pkg.purged:
    - name: 'xinetd'
{% else %}
notice_V38584-notPresent:
  cmd.run:
    - name: 'echo "The xinetd subsystem is not installed"'
{% endif %}
