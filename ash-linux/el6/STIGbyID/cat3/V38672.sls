# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38672
# Finding ID:	V-38672
# Version:	RHEL-06-000289
# Finding Level:	Low
#
#     The netconsole service must be disabled unless required. The 
#     "netconsole" service is not necessary unless there is a need to debug 
#     kernel panics, which is not common.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

{%- set stigId = 'V38672' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- set svcName = 'netconsole' %}

{%- if salt.pkg.version('initscripts') %}
# Ensure netconsole service is disabled and deactivated
  {%- if salt.service.enabled(svcName) %}
svc_{{ stigId }}-{{ svcName }}Disabled:
  service.disabled:
    - name: '{{ svcName }}'
notify_{{ stigId }}-{{ svcName }}Disabled:
  cmd.run:
    - name: 'echo "The ''{{ svcName }}'' service has been disabled"'
  {%- else %}
notify_{{ stigId }}-{{ svcName }}Disabled:
  cmd.run:
    - name: 'echo "The ''{{ svcName }}'' service is already disabled"'
  {%- endif %}

  {%- if salt.service.status(svcName) %}
svc_{{ stigId }}-{{ svcName }}Dead:
  service.dead:
    - name: '{{ svcName }}'

notify_{{ stigId }}-{{ svcName }}Dead:
  cmd.run:
    - name: 'echo "The ''{{ svcName }}'' service has been stopped"'

  {%- else %}
 
notify_{{ stigId }}-{{ svcName }}Dead:
  cmd.run:
    - name: 'echo "The ''{{ svcName }}'' service is already stopped"'

  {%- endif %}
{%- else %}

notify_{{ stigId }}-package:
  cmd.run:
    - name: 'echo "Parent package of {{ svcName }} not installed"'

{%- endif %}
