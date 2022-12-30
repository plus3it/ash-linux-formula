# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230368
# Rule ID:    SV-230368r810414_rule
# STIG ID:    RHEL-08-020221
# SRG ID:     SRG-OS-000077-GPOS-00045
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must be configured in the system-auth file to prohibit
#       password reuse for a minimum of five generations.
#
# References:
#   CCI:
#     - CCI-000200
#   NIST SP 800-53 :: IA-5 (1) (e)
#   NIST SP 800-53A :: IA-5 (1).1 (v)
#   NIST SP 800-53 Revision 4 :: IA-5 (1) (e)
#
###########################################################################
{%- set stig_id = 'RHEL-08-020221' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/pam.d/system-auth' %}
{%- if salt.file.is_link(targFile) %}
  {%- set targFile = salt.cmd.run('readlink -f ' + targFile) %}
{%- endif %}
{%- set searchRoot = '^password\s+required\s+pam_pwhistory.so\s+' %}

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
  # Entry exists and is correct
  {%- if salt.file.search(targFile, searchRoot + '.*remember=5') %}
file_{{ stig_id }}-{{ targFile }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found target config in {{ targFile }}.''\n"'
    - cwd: /root
    - stateful: True
  # Entry exists and is incorrect
  {%- elif salt.file.search(targFile, searchRoot) %}
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^(?P<srctok>{{ searchRoot }}.*$)'
    - repl: '\g<srctok> remember=5'
  # Entry is missing
  {%- else %}
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^(?P<srctok>^password\s+requisite\s+pam_pwquality.so.*)'
    - repl: '\g<srctok>\npassword required pam_pwhistory.so remember=5'
  {%- endif %}
{%- endif %}

