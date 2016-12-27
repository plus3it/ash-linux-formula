# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38620
# Finding ID:	V-38620
# Version:	RHEL-06-000247
# Finding Level:	Medium
#
#     Enabling the "ntpd" service ensures that the "ntpd" service will be 
#     running and that the system will synchronize its time to any servers 
#     specified. This is important whether the system is configured to be a 
#     client (and synchronize only its own clock) or it is also acting as 
#     an NTP server to other systems. Synchronizing time is essential for 
#     authentication services such as Kerberos, but it is also important 
#     for maintaining accurate logs and auditing possible security breaches.
#
#  CCI: CCI-000160
#  NIST SP 800-53 :: AU-8 (1)
#  NIST SP 800-53A :: AU-8 (1).1 (iii)
#
############################################################
{%- set stigId = 'V38620' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set svcNam = 'ntp' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if not salt.pkg.version(svcNam) %}
pkg_{{ stigId }}-{{ svcNam }}:
  pkg.installed:
    - name: '{{ svcNam }}'
{%- endif %}

svc_{{ stigId }}-{{ svcNam }}Enabled:
  service.enabled:
    - name: '{{ svcNam }}d'

svc_{{ stigId }}-{{ svcNam }}Running:
  service.running:
    - name: '{{ svcNam }}d'
