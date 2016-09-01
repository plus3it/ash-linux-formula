# Finding ID:	RHEL-07-020090
# Version:	RHEL-07-020090_rule
# SRG ID:	SRG-OS-000324-GPOS-00125
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must prevent non-privileged users from
#	executing privileged functions to include disabling,
#	circumventing, or altering implemented security
#	safeguards/countermeasures.
#
# CCI-002165 
# CCI-002235 
#    NIST SP 800-53 Revision 4 :: AC-3 (4) 
#    NIST SP 800-53 Revision 4 :: AC-6 (10) 
#
#################################################################
{%- set stig_id = 'RHEL-07-020090' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

