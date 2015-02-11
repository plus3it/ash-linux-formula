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
#  CCI: CCI-000374
#  NIST SP 800-53 :: CM-6 (2)
#  NIST SP 800-53A :: CM-6 (2).1 (ii)
#
############################################################

script_V38695-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38695.sh

notice_V38695:
  cmd.run:
    - name: 'echo "Implementation is system- and tenant-specific. This test will look for scheduled service in typical scheduler file locations. However, this tool cannot verify outside those locations or any frequencies discovered within those locations. **MANUAL VERIFICAION WILL BE REQUIRED.**"'
{% if not salt['pkg.verify']('aide') %}

warn_V38695-aideConf:
  cmd.run:
    - name: 'echo "Package unmodified (AIDE has not been configured)"'
{% endif %}

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
