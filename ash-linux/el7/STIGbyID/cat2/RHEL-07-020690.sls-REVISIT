# Finding ID:	RHEL-07-020690
# Version:	RHEL-07-020690_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All files and directories contained in local interactive user
#	home directories must be group-owned by a group of which the
#	home directory owner is a member.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-020690' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Thoughts on remediation:
# Need to:
#   1) Identify all local users with uid > SYS_MAX
#   2) Identify (each) user's primary and secondary groups
#   3) (iteratively) Determine (each) user's home-directory
#   4) Do a find against their home directory
#   5) Create a KVP dictionary with each found file/directory as the key and 
#      the group-owner as the value.
#   6) If current group-owner value for file is not in the user's primary or 
#      secondary groups, change the group-ownership to the user's primary
#      group.
