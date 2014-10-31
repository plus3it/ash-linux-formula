# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38695
# Finding ID:	V-38695
# Version:	RHEL-06-000302
# Finding Level:	Medium
#
#     A file integrity tool must be used at least weekly to check for 
#     unauthorized file changes, particularly the addition of unauthorized 
#     system libraries or binaries, or for unauthorized modification to 
#     authorized system libraries or binaries. By default, AIDE does not 
#     install itself for periodic execution. Periodically running AIDE may 
#     reveal unexpected changes in installed files.
#
############################################################

script_V38695-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38695.sh

{% if not salt['file.search']('/etc/crontab', '/usr/sbin/aide') %}
msg_V38695-etcCrontab:
  cmd.run:
  - name: 'echo "Info: AIDE not found in /etc/crontab"'
{% else %}
msg_V38695-etcCrontab:
  cmd.run:
  - name: 'echo "Info: AIDE found in /etc/crontab"'
{% endif %}

{% if salt['file.file_exists']('/var/spool/cron/root') %}
  {% if not salt['file.search']('/var/spool/cron/root', '/usr/sbin/aide') %}
msg_V38695-rootCrontab:
  cmd.run:
  - name: 'echo "Info: AIDE not found in root users crontab (/var/spool/cron/root)"'
  {% else %}
msg_V38695-rootCrontab:
  cmd.run:
  - name: 'echo "Info: AIDE found in root users crontab (/var/spool/cron/root)"'
  {% endif %}
{% else %}
msg_V38695-rootCrontab:
  cmd.run:
  - name: 'echo "Info: root user has no crontab (/var/spool/cron/root)"'
{% endif %}
