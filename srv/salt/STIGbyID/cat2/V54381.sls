# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-54381
# Finding ID:	V-54381
# Version:	RHEL-06-000163
# Finding Level:        Medium
#
#     Administrators should be made aware of an inability to record 
#     audit records. If a separate partition or logical volume of 
#     adequate size is used, running low on space for audit records 
#     should never occur. 
#
# CCI: CCI-000366
# NIST SP 800-53 :: CM-6 b
# NIST SP 800-53A :: CM-6.1 (iv)
# NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################

script_V54381-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V54381.sh

{% set checkFile = '/etc/audit/auditd.conf' %}
{% set auditParm = 'admin_space_left_action' %}

{% if salt['file.search'](checkFile, '^' + auditParm) %}
  {% if salt['file.search'](checkFile, '^' + auditParm + ' = suspend') %}
notify_V54381:
  cmd.run:
  - name 'echo "{{ auditParm }} parameter already set in {{ checkFile }}"'
  {% else %}
notify_V54381:
  cmd.run:
  - name 'echo "{{ auditParm }} parameter set in {{ checkFile }} but not to recommended value (''suspend'')"'

file_V54381:
  file.replace:
  - name: '{{ checkFile }}'
  - pattern: '^{{ auditParm }}'
  - repl: '{{ auditParm }} = suspend'
  {% endif %}
{% else %}
file_V54381:
  file.append:
  - name: '{{ checkFile }}'
  - text: '{{ auditParm }} = suspend'
{% endif %}
