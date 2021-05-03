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
{%- set stig_id = 'RHEL-07-010020' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
# Check for (and fix as necessary) RPMs with bad MD5s
fix_{{ stig_id }}-perms:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}_helper.sh
    - cwd: '/root'
    - stateful: True
{%- endif %}
