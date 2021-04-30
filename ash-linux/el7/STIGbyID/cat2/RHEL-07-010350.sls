# STIG ID:	RHEL-07-010350
# Rule ID:	SV-86573r3_rule
# Vuln ID:	V-71949
# SRG ID:	SRG-OS-000373-GPOS-00156
# Finding Level:	medium
#
# Rule Summary:
#	Users must re-authenticate for privilege escalation.
#
# CCI-002038
#    NIST SP 800-53 Revision 4 :: IA-11
#
#################################################################
{%- set stig_id = 'RHEL-07-010350' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set sudoerFiles = [ '/etc/sudoers' ] %}
{%- set sudoerFiles = sudoerFiles + salt.file.find('/etc/sudoers.d', maxdepth=1, type='f') %}

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
  {%- for sudoer in sudoerFiles %}
    {%- if salt.file.search(sudoer, '^[a-zA-Z%@].*!authenticate') %}
notify_{{ stig_id }}-{{ sudoer }}:
  cmd.run:
    - name: 'printf "[WARNING]:\tThe {{ sudoer }} file contains an active ''!authenticate''\n\t\tentry. Sites using only key-based logins should ignore this warning.\n" > /dev/stderr'
    - cwd: /root
    {%- endif %}
  {%- endfor %}
{%- endif %}
