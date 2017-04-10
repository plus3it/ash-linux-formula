# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38457
# Finding ID:	V-38457
# Version:	RHEL-06-000041
# Finding Level:	Medium
#
#     The /etc/passwd file must have mode 0644 or less permissive. If the
#     "/etc/passwd" file is writable by a group-owner or the world the risk
#     of its compromise is increased. The file contains the list of
#     accounts on the system and associated information, and ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38457' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

file_{{ stigId }}:
  file.managed:
    - name: '/etc/passwd'
    - mode: '0644'
    - replace: False
