# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38582
# Finding ID:	V-38582
# Version:	RHEL-06-000203
# Finding Level:	Medium
#
#     The xinetd service must be disabled if no network services utilizing 
#     it are enabled. The xinetd service provides a dedicated listener 
#     service for some programs, which is no longer necessary for 
#     commonly-used network services. Disabling it ensures that these 
#     uncommon services are not running, and also prevents attacks against
#     xinetd itself.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53 :: CM-7.1 (iii)
#  NIST SP 800-53 :: CM-7 b
#
############################################################

script_V38582-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38582.sh

{% if salt['pkg.version']('xinetd') %}
svc_V38582-xinetd:
  service.disabled:
    - name: 'xinetd'
{% endif %}
