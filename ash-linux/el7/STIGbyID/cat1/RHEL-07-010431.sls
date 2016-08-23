# Finding ID:	RHEL-07-010431
# Version:	RHEL-07-010431_rule
# SRG ID:	SRG-OS-000480-GPOS-00229
# Finding Level:	high
# 
# Rule Summary:
#	The operating system must not allow guest logon to the system.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- stig_id = 'RHEL-07-010431' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
