# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38627
# Finding ID:	V-38627
# Version:	RHEL-06-000256
# Finding Level:	Low
#
#     The openldap-servers package must not be installed unless required. 
#     Unnecessary packages should not be installed to decrease the attack 
#     surface of the system.
#
############################################################

script_V38627-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38627.sh

{% if salt['pkg.version']('openldap-servers') %}
svc_V38627-openldapEnabled:
  service.disabled:
    - name: 'slapd'

svc_V38627-openldapRunning:
  service.dead:
    - name: 'slapd'

pkg_V38627-remove:
  pkg.removed:
    - name: 'openldap-servers'
{% else %}
notice_V38627-notPresent:
  cmd.run:
    - name: 'echo "The openldap-servers subsystem is not installed"'
{% endif %}
