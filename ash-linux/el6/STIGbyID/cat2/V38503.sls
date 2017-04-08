# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38503
# Finding ID:	V-38503
# Version:	RHEL-06-000034
# Finding Level:	Medium
#
#     The /etc/shadow file must be group-owned by root. The "/etc/shadow"
#     file stores password hashes. Protection of this file is critical for
#     system security.
#
#  CCI: CCI-000366
#  NIST 800-53 :: CM-6 b
#  NIST 800-53A :: CM-6.1 (iv)
#  NIST 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38503' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

file_{{ stigId }}:
  file.managed:
    - name: /etc/shadow
    - group: root
    - replace: False
