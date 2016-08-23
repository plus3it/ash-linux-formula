# Finding ID:	RHEL-07-010460
# Version:	RHEL-07-010460_rule
# SRG ID:	SRG-OS-000080-GPOS-00048
# Finding Level:	high
#
# Rule Summary:
#	Systems with a Basic Input/Output System (BIOS) must
#	require authentication upon booting into single-user and
#	maintenance modes.
#
# CCI-000213
#    NIST SP 800-53 :: AC-3
#    NIST SP 800-53A :: AC-3.1
#    NIST SP 800-53 Revision 4 :: AC-3
#
#################################################################
{%- stig_id = 'RHEL-07-010460' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
