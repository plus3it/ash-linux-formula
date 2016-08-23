# Finding ID:	RHEL-07-010010
# Version:	RHEL-07-010010_rule
# SRG ID:	SRG-OS-000257-GPOS-00098
# Finding Level:	high
#
# Rule Summary:
#	The file permissions, ownership, and group membership of
#	system files and commands must match the vendor values.
#
# CCI-001494 CCI-001496
#    NIST SP 800-53 :: AU-9
#    NIST SP 800-53A :: AU-9.1
#    NIST SP 800-53 Revision 4 :: AU-9
#    NIST SP 800-53 :: AU-9 (3)
#    NIST SP 800-53A :: AU-9 (3).1
#    NIST SP 800-53 Revision 4 :: AU-9 (3)
#
#################################################################

{%- set stig_id = 'RHEL-07-010010' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Check (and fix as necessary) RPM-owned file permissions
fix_{{ stig_id }}-perms:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}_helper.sh
    - cwd: '/root'
    - stateful: True
