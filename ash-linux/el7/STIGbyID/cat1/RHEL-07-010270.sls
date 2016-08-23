# Finding ID:	RHEL-07-010270
# Version:	RHEL-07-010270_rule
# SRG ID:	SRG-OS-000106-GPOS-00053
# Finding Level:	high
# 
# Rule Summary:
#	The SSH daemon must not allow authentication using an empty password.
#
# CCI-000766 
#    NIST SP 800-53 :: IA-2 (2) 
#    NIST SP 800-53A :: IA-2 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-2 (2) 
#
#################################################################
{%- stig_id = 'RHEL-07-010270' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
