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

script_V38445-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38445.sh

notify_V38445-status:
  cmd.run:
    - name: 'echo "Info: recursing ''/var/log/audit'' to reset group-ownerships."'

{% set fileList = salt['file.find']("/var/log/audit", type='f') %}
{% for fileCheck in fileList %}
{% if not salt['file.get_group'](fileCheck) == 'root' %}
notify_V38445-{{ fileCheck }}:
  cmd.run:
    - name: 'echo "Info: resetting ''{{ fileCheck }}'' group-ownership to ''root''."'

file_V38445-{{ fileCheck }}:
  file.managed:
    - name: '{{ fileCheck }}'
    - group: 'root'
    - replace: 'False'
{% endif %}
{% endfor %}
