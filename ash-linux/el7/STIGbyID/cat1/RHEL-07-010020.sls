# Finding ID:	RHEL-07-010020
# Version:	RHEL-07-010020_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The cryptographic hash of system files and commands must match vendor values.
#
# CCI-000663 
#    NIST SP 800-53 :: SA-7 
#    NIST SP 800-53A :: SA-7.1 (ii) 
#
#################################################################
{%- stig_id = 'RHEL-07-010020' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
