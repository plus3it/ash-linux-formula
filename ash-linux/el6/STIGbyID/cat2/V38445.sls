# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38445
# Finding ID:	V-38445
# Version:	RHEL-06-000522
# Finding Level:	Medium
#
#     Audit log files must be group-owned by root. If non-privileged users
#     can write to audit logs, audit trails can be modified or destroyed.
#
#  CCI: <None specified in DISA documentation>
#  NIST SP 800-53 :: <None specified in DISA documentation>
#
############################################################

{%- set stigId = 'V38445' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkDir = '/var/log/audit' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

notify_{{ stigId }}-status:
  cmd.run:
    - name: 'echo "Info: recursing ''{{ chkDir }}'' to reset group-ownerships."'

{%- set fileList = salt['file.find'](chkDir, type='f') %}
{%- for fileCheck in fileList %}
{%- if not salt.file.get_group(fileCheck) == 'root' %}
notify_{{ stigId }}-{{ fileCheck }}:
  cmd.run:
    - name: 'echo "Info: resetting ''{{ fileCheck }}'' group-ownership to ''root''."'

file_{{ stigId }}-{{ fileCheck }}:
  file.managed:
    - name: '{{ fileCheck }}'
    - group: 'root'
    - replace: False
{%- endif %}
{%- endfor %}
