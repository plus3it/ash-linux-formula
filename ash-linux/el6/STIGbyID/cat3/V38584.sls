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

{%- set stigId = 'V38584' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set svcName = 'xinetd' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version(svcName) %}
svc_{{ stigId }}-{{ svcName }}Enabled:
  service.disabled:
    - name: '{{ svcName }}'

svc_{{ stigId }}-{{ svcName }}Running:
  service.dead:
    - name: '{{ svcName }}'

pkg_{{ stigId }}-remove:
  pkg.purged:
    - name: '{{ svcName }}'
{%- else %}
notice_{{ stigId }}-notPresent:
  cmd.run:
    - name: 'echo "The {{ svcName }} subsystem is not installed"'
{%- endif %}
