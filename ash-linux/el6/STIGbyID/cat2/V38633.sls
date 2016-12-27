# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38633
# Finding ID:	V-38633
# Version:	RHEL-06-000160
# Finding Level:	Medium
#
#     The system must set a maximum audit log file size. The total storage 
#     for audit log files must be large enough to retain log information 
#     over the period required. This is a function of the maximum log file 
#     size and the number of logs retained.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38633' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- set auditConf = '/etc/audit/auditd.conf' %}
{%- set logParm = 'max_log_file' %}

{%- if salt.file.search(auditConf, '^' + logParm + ' = ') %}
  {%- if salt.file.search(auditConf, '^' + logParm + ' = 6') %}
notify_{{ stigId }}-Set:
  cmd.run:
    - name: 'echo "''{{ logParm }}'' value in ''{{ auditConf }}'' already matches recommended value [6]"'
  {%- else %}
notify_{{ stigId }}-Set:
  cmd.run:
    - name: 'echo "Setting ''{{ logParm }}'' value in ''{{ auditConf }}'' to match STIG recommended value [6]"'

file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ auditConf }}'
    - pattern: '^{{ logParm }} = .*$'
    - repl: '{{ logParm }} = 6'
  {%- endif %}

{%- else %}
notify_{{ stigId }}-Set:
  cmd.run:
    - name: 'echo "Setting ''{{ logParm }}'' value in ''{{ auditConf }}'' to match STIG recommended value [6]"'

file_{{ stigId }}-append:
  file.append:
    - name: '{{ auditConf }}'
    - text: '{{ logParm }} = 6'
{%- endif %}
