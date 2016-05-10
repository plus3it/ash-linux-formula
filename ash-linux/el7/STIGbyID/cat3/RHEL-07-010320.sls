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
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set privUser = 'root'%}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

script_{{ stig_id }}-noExpire:
  cmd.script:
    - name: '{{ stig_id }}-check_fix.sh "{{ privUser }}"'
    - source: 'salt://{{ helperLoc }}/{{ stig_id }}-check_fix.sh'
    - cwd: '/root'
    - stateful: True
    - require:
      - cmd: script_{{ stig_id }}-describe
