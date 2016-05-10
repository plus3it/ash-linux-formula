# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38590
# Finding ID:	V-38590
# Version:	RHEL-06-000071
# Finding Level:	Low
#
#     The system must allow locking of the console screen in text mode. 
#     Installing "screen" ensures a console locking capability is available 
#     for users who may need to suspend console logins.
#
#  CCI: CCI-000058
#  NIST SP 800-53 :: AC-11 a
#  NIST SP 800-53A :: AC-11
#  NIST SP 800-53 Revision 4 :: AC-11 a
#
############################################################

{%- set stigId = 'V38590' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set svcName = 'screen' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

pkg_{{ stigId }}-{{ svcName }}:
  pkg.installed:
    - name: '{{ svcName }}'
