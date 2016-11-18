# Finding ID:	RHEL-07-040260
# Version:	RHEL-07-040260_rule
# SRG ID:	SRG-OS-000423-GPOS-00187
# Finding Level:	medium
# 
# Rule Summary:
#	All networked systems must have SSH installed.
#
# CCI-002418 
# CCI-002421 
# CCI-002420 
# CCI-002422 
#    NIST SP 800-53 Revision 4 :: SC-8 
#    NIST SP 800-53 Revision 4 :: SC-8 (1) 
#    NIST SP 800-53 Revision 4 :: SC-8 (2) 
#    NIST SP 800-53 Revision 4 :: SC-8 (2) 
#
#################################################################
{%- set stig_id = 'RHEL-07-040260' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

packages_{{ stig_id }}-installed:
  pkg.installed:
    - pkgs:
      - openssh-clients
      - openssh-server
