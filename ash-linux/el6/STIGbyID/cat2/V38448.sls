# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38448
# Finding ID:	V-38448
# Version:	RHEL-06-000037
# Finding Level:	Medium
#
#     The /etc/gshadow file must be group-owned by root. The "/etc/gshadow"
#     file contains group password hashes. Protection of this file is
#     critical for system security.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38448' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/gshadow' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.get_group(checkFile) == 'root' %}
notify_{{ stigId }}-ownership:
  cmd.run:
    - name: 'echo "Info: ''{{ checkFile }}'' file already group-owned by ''root''."'
{%- else %}
notify_{{ stigId }}-ownership:
  cmd.run:
    - name: 'echo "WARNING: ''{{ checkFile }}'' not group-owned by ''root''. Fixing..."'

file_{{ stigId }}-setOwn:
  file.managed:
    - name: '{{ checkFile }}'
    - group: 'root'
    - replace: False
{%- endif %}
