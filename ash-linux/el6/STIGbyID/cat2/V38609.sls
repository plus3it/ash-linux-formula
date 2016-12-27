# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38609
# Finding ID:	V-38609
# Version:	RHEL-06-000223
# Finding Level:	Medium
#
#     The TFTP service must not be running. Disabling the "tftp" service 
#     ensures the system is not acting as a tftp server, which does not 
#     provide encryption or authentication.
#
#  CCI: CCI-001436
#  NIST SP 800-53 :: AC-17 (8)
#  NIST SP 800-53A :: AC-17 (8).1 (ii)
#
############################################################

{%- set stigId = 'V38609' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.pkg.version('tftp-server') %}
svc_{{ stigId }}-tfptd:
  service.disabled:
    - name: 'tftp-server'
{%- endif %}

cmd_{{ stigId }}-tfptd:
  cmd.run:
    - name: 'echo "TFTP service not installed"'
