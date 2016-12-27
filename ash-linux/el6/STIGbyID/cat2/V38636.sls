# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38636
# Finding ID:	V-38636
# Version:	RHEL-06-000159
# Finding Level:	Medium
#
#     The system must retain enough rotated audit logs to cover the 
#     required log retention period. The total storage for audit log files 
#     must be large enough to retain log information over the period 
#     required. This is a function of the maximum log file size and the 
#     number of logs retained.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38636' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/audit/auditd.conf' %}
{%- set checkPtn = 'num_logs' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.pkg.version('audit') and salt.file.search(checkFile, '^' + checkPtn) %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^{{ checkPtn }}.*$'
    - repl: '{{ checkPtn }} = 5'
{%- elif salt.pkg.version('audit') and not salt.file.search(checkFile, '^' + checkPtn) %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ checkFile }}'
    - text: |
        
        # system must retain enough rotated logs to meet local policy (per STIG V-38636)
        {{ checkPtn }} = 5
{%- endif %}

