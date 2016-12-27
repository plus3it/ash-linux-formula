# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38670
# Finding ID:	V-38670
# Version:	RHEL-06-000306
# Finding Level:	Medium
#
#     The operating system must detect unauthorized changes to software and 
#     information. By default, AIDE does not install itself for periodic 
#     execution. Periodically running AIDE may reveal unexpected changes in 
#     installed files.
#
#  CCI: CCI-001297
#  NIST SP 800-53 :: SI-7
#  NIST SP 800-53A :: SI-7.1
#
############################################################
{%- set stigId = 'V38670' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set cronRoot = '/var/spool/cron/root' %}
{%- set cronEtc = '/etc/crontab' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

notice_{{ stigId }}:
  cmd.run:
    - name: 'echo "Implementation is system- and tenant-specific. This test will look for scheduled service in typical scheduler file locations. However, this tool cannot verify outside those locations or any frequencies discovered within those locations. **MANUAL VERIFICAION WILL BE REQUIRED.**"'

{%- if not salt.pkg.verify('aide') %}
warn_{{ stigId }}-aideConf:
  cmd.run:
    - name: 'echo "Package unmodified (AIDE has not been configured)"'
{%- endif %}

{%- if not salt.file.search(cronEtc, '/usr/sbin/aide') %}
msg_{{ stigId }}-etcCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE not found in {{ cronEtc }}"'
{%- else %}
msg_{{ stigId }}-etcCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE found in {{ cronEtc }}"'
{%- endif %}

{%- if salt.file.file_exists(cronRoot) %}
  {%- if not salt.file.search(cronRoot, '/usr/sbin/aide') %}
msg_{{ stigId }}-rootCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE not found in root users crontab ({{ cronRoot }})"'
  {%- else %}
msg_{{ stigId }}-rootCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE found in root users crontab ({{ cronRoot }})"'
  {%- endif %}
{%- else %}
msg_{{ stigId }}-rootCrontab:
  cmd.run:
    - name: 'echo "Info: root user has no crontab ({{ cronRoot }})"'
{%- endif %}
