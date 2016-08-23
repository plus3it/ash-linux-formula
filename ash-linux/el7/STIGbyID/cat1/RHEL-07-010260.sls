# Finding ID:	RHEL-07-010260
# Version:	RHEL-07-010260_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The system must not have accounts configured with blank or null passwords.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- stig_id = 'RHEL-07-010260' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
