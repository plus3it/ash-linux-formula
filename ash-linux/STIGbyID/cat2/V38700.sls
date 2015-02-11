# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38700
# Finding ID:	V-38700
# Version:	RHEL-06-000305
# Finding Level:	Medium
#
#     The operating system must provide a near real-time alert when any of 
#     the organization defined list of compromise or potential compromise 
#     indicators occurs. By default, AIDE does not install itself for 
#     periodic execution. Periodically running AIDE may reveal unexpected 
#     changes in installed files.
#
#  CCI: CCI-001263
#  NIST SP 800-53 :: SI-4 (5)
#  NIST SP 800-53A :: SI-4 (5).1 (ii)
#
#
############################################################

script_V38700-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38700.sh

notice_V38700:
  cmd.run:
    - name: 'echo "Implementation is system- and tenant-specific. This test will look for scheduled service in typical scheduler file locations. However, this tool cannot verify outside those locations or any frequencies discovered within those locations. **MANUAL VERIFICAION WILL BE REQUIRED.**"'

{% if not salt['pkg.verify']('aide') %}
warn_V38700-aideConf:
  cmd.run:
    - name: 'echo "Package unmodified (AIDE has not been configured)"'
{% endif %}

{% if not salt['file.search']('/etc/crontab', '/usr/sbin/aide') %}
msg_V38700-etcCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE not found in /etc/crontab"'
{% else %}
msg_V38700-etcCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE found in /etc/crontab"'
{% endif %}

{% if salt['file.file_exists']('/var/spool/cron/root') %}
  {% if not salt['file.search']('/var/spool/cron/root', '/usr/sbin/aide') %}
msg_V38700-rootCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE not found in root users crontab (/var/spool/cron/root)"'
  {% else %}
msg_V38700-rootCrontab:
  cmd.run:
    - name: 'echo "Info: AIDE found in root users crontab (/var/spool/cron/root)"'
  {% endif %}
{% else %}
msg_V38700-rootCrontab:
  cmd.run:
    - name: 'echo "Info: root user has no crontab (/var/spool/cron/root)"'
{% endif %}
