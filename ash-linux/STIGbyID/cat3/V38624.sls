# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38624
# Finding ID:	V-38624
# Version:	RHEL-06-000138
# Finding Level:	Low
#
#     System logs must be rotated daily. Log files that are not properly 
#     rotated run the risk of growing so large that they fill up the 
#     /var/log partition. Valuable logging information could be lost if the 
#     /var/log partition becomes full.
#
############################################################

script_V38624-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38624.sh

{% if not salt['pkg.version']('logrotate') %}
V38624.sls:
pkg_V38624-logrotate:
  pkg.installed:
    - name: 'logrotate'
{% endif %}

{% if salt['file.search']('/var/log/cron', ' logrotate$') %}
msg_V38624-status:
  cmd.run:
    - name: 'echo "Logrotate service already configured to run"'
{% else %}
  {% if not salt['file.file_exists']('/etc/cron.daily/logrotate') %}
msg_V38624-status:
  cmd.run:
    - name: 'echo "Logrotate not correctly-installed. Correcting..."'

pkg_V38624-logrotate:
  pkg.installed:
    - name: 'logrotate'
    - reinstall: 'True'
  {% else %}
msg_V38624-status:
  cmd.run:
    - name: 'echo "Logrotate not found in cron log: manual verification required"'
  {% endif %}
{% endif %}
