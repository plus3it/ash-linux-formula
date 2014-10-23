# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38609
# Finding ID:	V-38609
# Version:	RHEL-06-000223
# Finding Level:	Medium
#
#     The TFTP service must not be running. Disabling the "tftp" service 
#     ensures the system is not acting as a tftp server, which does not 
#     provide encryption or authentication.
#
############################################################

script_V38609-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38609.sh

{% if salt['pkg.version']('tftp-server') %}
svc_V38609-tfptd:
  service.disabled:
  - name: 'tftp-server'
{% endif %}

cmd_V38609-tfptd:
  cmd.run:
  - name: 'echo "TFTP service not installed"'
