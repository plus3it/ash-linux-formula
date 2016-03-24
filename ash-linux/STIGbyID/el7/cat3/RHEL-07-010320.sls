# STIG URL:
# Finding ID:	RHEL-07-010320
# Version:	RHEL-07-010320_rule
# SRG ID:	SRG-OS-000123-GPOS-00064
# Finding Level:	low
#
# Rule Summary:
#     The operating system must be configured such that emergency 
#     administrator accounts are never automatically removed or 
#     disabled.
#
# CCI-001682
#    NIST SP 800-53 :: AC-2 (2)
#    NIST SP 800-53A :: AC-2 (2).1 (ii)
#    NIST SP 800-53 Revision 4 :: AC-2 (2)
#
#################################################################
{%- set stig_id = 'RHEL-07-010320' %}
{%- set helperLoc = 'ash-linux/STIGbyID/el7/cat3/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
