# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38698
# Finding ID:	V-38698
# Version:	RHEL-06-000304
# Finding Level:	Medium
#
#     The operating system must employ automated mechanisms to detect the 
#     presence of unauthorized software on organizational information 
#     systems and notify designated organizational officials in accordance 
#     with the organization defined frequency. By default, AIDE does not 
#     install itself for periodic execution. Periodically running AIDE may 
#     reveal unexpected changes in installed files.
#
#  CCI: CCI-001069
#  NIST SP 800-53 :: RA-5 (7)
#  NIST SP 800-53A :: RA-5 (7).1 (ii)
#
############################################################

{%- set stigId = 'V38698' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

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

{%- if not salt.file.search('/etc/crontab', '/usr/sbin/aide') %}
msg_{{ stigId }}-etcCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE not found in /etc/crontab"'
{%- else %}
msg_{{ stigId }}-etcCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE found in /etc/crontab"'
{%- endif %}

{%- if salt.file.file_exists('/var/spool/cron/root') %}
  {%- if not salt.file.search('/var/spool/cron/root', '/usr/sbin/aide') %}
msg_{{ stigId }}-rootCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE not found in root users crontab (/var/spool/cron/root)"'
  {%- else %}
msg_{{ stigId }}-rootCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE found in root users crontab (/var/spool/cron/root)"'
  {%- endif %}
{%- else %}
msg_{{ stigId }}-rootCrontab:
  cmd.run:
    - name: 'echo "Info: root user has no crontab (/var/spool/cron/root)"'
{%- endif %}
