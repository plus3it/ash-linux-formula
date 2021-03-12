# Finding ID:	RHEL-07-010372
# Version:	RHEL-07-010372_rule
# SRG ID:	SRG-OS-000329-GPOS-00128
# Finding Level:	medium
#
# Rule Summary:
#	Accounts subject to three unsuccessful login attempts within
#	15 minutes must be locked for the maximum configurable period.
#
# CCI-002238
#    NIST SP 800-53 Revision 4 :: AC-7 b
#
#################################################################
{%- set stig_id = 'RHEL-07-010372' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pamFiles = [
                    '/etc/pam.d/system-auth',
                    '/etc/pam.d/password-auth'
                     ] %}
{%- set pamMod = 'pam_faillock.so' %}
{%- set parmName = 'unlock_time' %}
{%- set parmValu = salt.pillar.get('ash-linux:lookup:faillock:' + parmName, '900') %}
{%- set preAuth =  'auth        required      ' + pamMod + ' preauth silent audit deny=3 ' %}
{%- set authFail = 'auth        [default=die] ' + pamMod + ' authfail deny=3 ' %}
{%- set authSucc = 'auth        required      ' + pamMod + ' authsucc deny=3 ' %}

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
#define macro to configure the dirctive-anchors to host the faillock parm/vals
  {%- macro pammod_template(stig_id, file, pam_module, preauth, authfail, authsucc) %}
insert_{{ stig_id }}-{{ file }}_faillock:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<srctok>auth[ \t]*[a-z]*[ \t]*pam_unix.so.*$)'
    - repl: '{{ preauth }}\n\g<srctok>\n{{ authfail }}\n{{ authsucc }}'
    - onlyif:
      - 'test $(grep -c -E -e "{{ pam_module }}" {{ file }}) -eq 0'
  {%- endmacro %}

# Iterate files to alter...
  {%- for checkFile in pamFiles %}
  # Identify proper target to modify - probably redundant in newer,
  # symlink-following releases of SaltStack
    {%- if salt.file.is_link(checkFile) %}
      {%- set checkFile = checkFile + '-ac' %}
    {%- endif %}

  # Check if faillock is present, fix if necessary
    {%- if not salt.file.search(checkFile, pamMod) %}

{{ pammod_template(stig_id, checkFile, pamMod, preAuth, authFail, authSucc) }}

    {%- endif %}
setVal_{{ stig_id }}-{{ checkFile }}:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^(?P<srctok>auth.*{{ pamMod }}.*)$'
    - repl: '\g<srctok> {{ parmName }}={{ parmValu }}'
    - unless: 'grep -q "{{ pamMod }}.*{{ parmName }}=" {{ checkFile }}'

fixVal_{{ stig_id }}-{{ checkFile }}:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '{{parmName }}=[0-9]*'
    - repl: '{{ parmName }}={{ parmValu }}'

  {%- endfor %}
{%- endif %}
