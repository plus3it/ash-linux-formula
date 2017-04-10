# Finding ID:	RHEL-07-040650
# Version:	RHEL-07-040650_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	The SSH private host key files must have mode 0600 or less permissive.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040650' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set keysList = salt['cmd.shell']('find / -name "ssh_host*key" -type f').split('\n') %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for key in keysList %}
file_{{ stig_id }}-{{ key }}:
  file.managed:
    - name: '{{ key }}'
    - mode: '0600'
    - replace: False
{%- endfor %}
