# Restart sshd service if any of:
# 
# Cause changes to the /etc/ssh/sshd_config file
#
#################################################################
{%- set stig_id = 'restart_sshd' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set svcName = 'sshd' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

service_sshd_restart:
  service.running:
    - name: '{{ svcName }}'
