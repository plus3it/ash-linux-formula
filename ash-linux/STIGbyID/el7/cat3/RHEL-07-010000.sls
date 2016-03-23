# STIG URL:
# Finding ID:	RHEL-07-010000
# Version:	RHEL-07-010000_rule
# SRG ID:	SRG-OS-000001-GPOS-00001
# Finding Level:	low
#
# Rule Summary:
#     The operating system must provide automated mechanisms for 
#     supporting account management functions.
#
# CCI-000015
#    NIST SP 800-53 :: AC-2 (1)
#    NIST SP 800-53A :: AC-2 (1).1
#    NIST SP 800-53 Revision 4 :: AC-2 (1)
#
#################################################################
{%- set stig_id = 'RHEL-07-010000' %}
{%- set chkPkg = 'sssd-common' %}
{%- set helperLoc = 'ash-linux/STIGbyID/el7/cat3/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt['pkg.version'](chkPkg) %}
{%- else %}
notify_{{ stig_id }}-presence-{{ chkPkg }}:
  cmd.run:
    - name: "printf \"changed=no comment='The {{ chkPkg }} subsystem \" ;
             printf \"is not installed.'\""
    - stateful: True
{%- endif %}

