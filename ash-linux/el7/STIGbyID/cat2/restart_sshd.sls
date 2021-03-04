# Restart sshd service if any of:
# 
# Cause changes to the /etc/ssh/sshd_config file
#
#################################################################
{%- set stig_id = 'SSHD_restart' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set svcName = 'sshd' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

service_sshd_restart:
  service.running:
    - name: '{{ svcName }}'
    - onchanges:
      - file: file_RHEL-07-040690-/etc/ssh/sshd_config
      - file: file_RHEL-07-040680-/etc/ssh/sshd_config
      - file: file_RHEL-07-040660-/etc/ssh/sshd_config
      - file: file_RHEL-07-040700-/etc/ssh/sshd_config
      - file: file_RHEL-07-040670-/etc/ssh/sshd_config
