# Finding ID:	RHEL-07-020210
# Version:	RHEL-07-020210_rule
# SRG ID:	SRG-OS-000445-GPOS-00199
# Finding Level:	high
# 
# Rule Summary:
#	The operating system must enable SELinux.
#
# CCI-002165 CCI-002696 
#    NIST SP 800-53 Revision 4 :: AC-3 (4) 
#    NIST SP 800-53 Revision 4 :: SI-6 a 
#
#################################################################
{%- stig_id = 'RHEL-07-020210' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
