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
############################################################

script_V38670-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38670.sh

{% if not salt['file.search']('/etc/crontab', '/usr/sbin/aide') %}
msg_V38670-etcCrontab:
  cmd.run:
  - name: 'echo "Info: AIDE not found in /etc/crontab"'
{% else %}
msg_V38670-etcCrontab:
  cmd.run:
  - name: 'echo "Info: AIDE found in /etc/crontab"'
{% endif %}

{% if not salt['file.search']('/var/spool/cron/root', '/usr/sbin/aide') %}
msg_V38670-etcCrontab:
  cmd.run:
  - name: 'echo "Info: AIDE not found in root user's crontab (/var/spool/cron/root)"'
{% else %}
msg_V38670-etcCrontab:
  cmd.run:
  - name: 'echo "Info: AIDE found in root user's crontab (/var/spool/cron/root)"'
{% endif %}
