# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38502
# Finding ID:	V-38502
# Version:	RHEL-06-000033
# Finding Level:	Medium
#
#     The /etc/shadow file must be owned by root. The "/etc/shadow" file
#     contains the list of local system accounts and stores password
#     hashes. Protection of this file is critical for system security.
#     Failure to give ownership of this file to root ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38502' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

file_{{ stigId }}:
  file.managed:
    - name: /etc/shadow
    - user: root
    - replace: False
