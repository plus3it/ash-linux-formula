# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38478
# Finding ID:	V-38478
# Version:	RHEL-06-000009
# Finding Level:	Low
#
#     Although systems management and patching is extremely important to 
#     system security, management by a system outside the enterprise 
#     enclave is not desirable for some environments. However, if the 
#     system is being managed by RHN or RHN Satellite Server the "rhnsd" 
#     daemon can remain on. 
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

{%- set stigId = 'V38478' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set svcName = 'rhnsd' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version(svcName) %}
# Ensure {{ svcName }} service is disabled and stopped
svc_{{ stigId }}-{{ svcName }}Disabled:
  service.disabled:
    - name: '{{ svcName }}'

svc_{{ stigId }}-{{ svcName }}Dead:
  service.dead:
    - name: '{{ svcName }}'
{%- else %}
cmd_{{ stigId }}-notice:
  cmd.run:
    - name: 'echo "The {{ svcName }} service not installed. No relevant findings possible."'
{%- endif %}
