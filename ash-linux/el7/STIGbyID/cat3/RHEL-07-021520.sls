# STIG URL:
# Finding ID:	RHEL-07-021520
# Version:	RHEL-07-021520_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The Network File System (NFS) export configuration file must 
#     have mode 0644 or less permissive.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021520' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set chkFile = '/etc/exports' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

file_{{ stig_id }}-exports:
  file.managed:
    - name: '{{ chkFile }}'
    - user: root
    - group: root
    - mode: 0644
