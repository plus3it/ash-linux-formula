# STIG URL:
# Finding ID:	RHEL-07-021240
# Version:	RHEL-07-021240_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     A separate file system must be used for user home directories 
#     (such as /home or an equivalent).
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021240' %}
{%- set helperLoc = 'ash-linux/STIGbyID/el7/cat3/files' %}
{%- set chkPtn = '/home' %}
{%- set chkSvc = 'home.mount' %}
{%- set chkFile = '/etc/fstab' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt['file.search'](chkFile, '[\s]' + chkPtn + '[\s]') %}
cmd_{{ stig_id }}-managed_by:
  cmd.run:
    - name: 'echo "{{ chkPtn }} managed via {{ chkFile }}"'
{%- elif salt['service.status'](chkSvc) %}
cmd_{{ stig_id }}-managed_by:
  cmd.run:
    - name: 'echo "{{ chkPtn }} managed via {{ chkSvc }} systemd service"'
{%- else %}
cmd_{{ stig_id }}-managed_by:
  cmd.run:
    - name: 'echo "{{ chkPtn }} is not a mounted filesystem. System NOT compliant with {{ stig_id }}"'
{%- endif %}
