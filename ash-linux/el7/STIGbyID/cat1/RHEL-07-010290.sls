# STIG ID:	RHEL-07-010290
# Rule ID:	SV-86561r3_rule
# Vuln ID:	V-71937
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The system must not have accounts configured with blank or null passwords.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-010290' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set sysauthroot = '/etc/pam.d/system-auth' %}
{%- if salt.file.file_exists(sysauthroot + '-ac') %}
  {%- set checkFile = sysauthroot + '-ac' %}
{%- else %}
  {%- set checkFile = sysauthroot %}
{%- endif %}

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
file_{{ stig_id }}-sysauth_ac:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '[	 ]*nullok[	 ]*'
    - repl: ' '
    - onlyif: 
      - 'test -f {{ checkFile }}'
{%- endif %}
