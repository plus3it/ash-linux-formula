# Finding ID:	RHEL-07-020370
# Version:	RHEL-07-020370_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All files and directories must have a valid group owner.
#
# CCI-002165 
#    NIST SP 800-53 Revision 4 :: AC-3 (4) 
#
#################################################################
{%- set stig_id = 'RHEL-07-020370' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

