# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38461
# Finding ID:	V-38461
# Version:	RHEL-06-000044
# Finding Level:	Medium
#
#     The /etc/group file must have mode 0644 or less permissive. The
#     "/etc/group" file contains information regarding groups that are
#     configured on the system. Protection of this file is important for
#     system security.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38461' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/group' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

file_{{ stigId }}:
  file.managed:
    - name: '{{ chkFile }}'
    - mode: '0644'
    - replace: False
