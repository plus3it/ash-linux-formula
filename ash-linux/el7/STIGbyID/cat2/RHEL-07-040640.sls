# Finding ID:	RHEL-07-040640
# Version:	RHEL-07-040640_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	The SSH public host key files must have mode 0644 or less permissive.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040640' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set keysList = salt['cmd.shell']('find / -name "*key.pub" -type f').split('\n') %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for key in keysList %}
file_{{ stig_id }}-{{ key }}:
  file.managed:
    - name: '{{ key }}'
    - mode: '0644'
    - replace: False
{%- endfor %}
