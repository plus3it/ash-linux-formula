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

{%- set stigId = 'V38604' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set svcList = [ 'ypbind', 'ypserv', 'yp-tools', ] %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- for svcNam in svcList %}
  {%- if salt.pkg.version(svcNam) %}
svc_{{ stigId }}-{{ svcNam }}:
  service.disabled:
    - name: '{{ svcNam }}'
  {%- endif %}
{%- endfor %}
