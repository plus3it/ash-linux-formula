# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38604
# Finding ID:	V-38604
# Version:	RHEL-06-000221
# Finding Level:	Medium
#
#     The ypbind service must not be running. Disabling the "ypbind" 
#     service ensures the system is not acting as a client in a NIS or NIS+ 
#     domain.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 a
#
############################################################

script_V38604-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38604.sh

{% if salt['pkg.version']('ypbind') %}
svc_V38604-ypbind:
  service.disabled:
  - name: 'ypbind'
{% endif %}

{% if salt['pkg.version']('ypserv') %}
svc_V38604-ypserv:
  service.disabled:
  - name: 'ypserv'
{% endif %}

{% if salt['pkg.version']('yp-tools') %}
svc_V38604-yptools:
  service.disabled:
  - name: 'yp-tools'
{% endif %}

