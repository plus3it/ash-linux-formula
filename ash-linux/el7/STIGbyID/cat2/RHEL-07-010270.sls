# STIG ID:	RHEL-07-010270
# Rule ID:	SV-86557r3_rule
# Vuln ID:	V-71933
# SRG ID:	SRG-OS-000077-GPOS-00045
# Finding Level:	medium
#
# Rule Summary:
#	Passwords must be prohibited from reuse for a minimum of five generations.
#
# CCI-000200
#    NIST SP 800-53 :: IA-5 (1) (e)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (e)
#
#################################################################
{%- set stig_id = 'RHEL-07-010270' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/pam.d/system-auth' %}
{%- if salt.file.is_link(targFile) %}
  {%- set targFile = targFile + '-ac' %}
{%- endif %}
{%- set searchRoot = '^password\s+sufficient\s+pam_unix.so\s+' %}

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
  {%- if salt.file.search(targFile, searchRoot + '.*remember=5') %}
file_{{ stig_id }}-{{ targFile }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found target config in {{ targFile }}.''\n"'
    - cwd: /root
    - stateful: True
  {%- elif salt.file.search(targFile, searchRoot) %}
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: {{ targFile }}
    - pattern: '^(?P<srctok>{{ searchRoot }}.*$)'
    - repl: '\g<srctok> remember=5'
file_{{ stig_id }}-{{ targFile }}-cleanup:
  file.replace:
    - name: {{ targFile }}
    - pattern: '(md5|bigcrypt|sha256|blowfish) '
    - repl: ''
    - onchanges:
      - file: file_{{ stig_id }}-{{ targFile }}
  {%- else %}
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: {{ targFile }}
    - pattern: '^(?P<srctok>^password\s+requisite\s+pam_pwquality.so.*)'
    - repl: '\g<srctok>\npassword sufficient pam_unix.so remember=5'
  {%- endif %}
{%- endif %}

