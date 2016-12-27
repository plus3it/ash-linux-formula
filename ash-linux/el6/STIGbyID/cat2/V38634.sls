# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38634
# Finding ID:	V-38634
# Version:	RHEL-06-000161
# Finding Level:	Medium
#
#     Automatically rotating logs (by setting this to "rotate") minimizes 
#     the chances of the system unexpectedly running out of disk space by 
#     being overwhelmed with log data. However, for systems that must never 
#     discard log data, or which use external processes to transfer it and 
#     reclaim space, "keep_logs" can be employed. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38634' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/audit/auditd.conf' %}
{%- set checkPtn = 'max_log_file_action' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.pkg.version('audit') and salt.file.search(checkFile, '^' + checkPtn) %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^{{ checkPtn }}.*$'
    - repl: '{{ checkPtn }} = rotate'
{%- elif salt.pkg.version('audit') and not salt.file.search(checkFile, '^' + checkPtn) %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ checkFile }}'
    - text: |
        
        # audit system must rotate logs (per STIG V-38634)
        {{ checkPtn }} = rotate
{%- endif %}

