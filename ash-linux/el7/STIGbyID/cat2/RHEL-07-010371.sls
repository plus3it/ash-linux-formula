# Finding ID:	RHEL-07-010371
# Version:	RHEL-07-010371_rule
# SRG ID:	SRG-OS-000329-GPOS-00128
# Finding Level:	medium
# 
# Rule Summary:
#	If three unsuccessful logon attempts within 15 minutes occur
#	the associated account must be locked.
#
# CCI-002238 
#    NIST SP 800-53 Revision 4 :: AC-7 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-010371' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pamFiles = [
                    '/etc/pam.d/system-auth',
                    '/etc/pam.d/password-auth'
                     ] %}
{%- set pamMod = 'pam_faillock.so' %}
{%- set parmName = 'fail_interval' %}
{%- set parmValu = salt.pillar.get('ash-linux:lookup:faillock:' + parmName, '900') %}
{%- set preAuth =  'auth        required      ' + pamMod + ' preauth silent audit deny=3 ' + parmName + '=' + parmValu %}
{%- set authFail = 'auth        [default=die] ' + pamMod + ' authfail deny=3 ' + parmName + '=' + parmValu %}
{%- set authSucc = 'auth        required      ' + pamMod + ' authsucc deny=3 ' + parmName + '=' + parmValu %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root


#define macro to configure the pam module in a file
{%- macro pammod_template(stig_id, file, pam_module, preauth, authfail, authsucc) %}
notify_{{ stig_id }}-{{ file }}_exists:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ pam_module }} was absent in {{ file }}.''\n"'
    - cwd: /root
    - stateful: True

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

  {%- if not salt.file.search(checkFile, pamMod) %}

#file {{ checkFile }} exists
#{{ pamMod }} not yet present in file
#Use macro to add necessary rules
{{ pammod_template(stig_id, checkFile, pamMod, preAuth, authFail, authSucc) }}

  {%- else %}

## notify_{{ stig_id }}-{{ checkFile }}_exists:
##   cmd.run:
##     - name: 'printf "\nchanged=no comment=''{{ pamMod }} already present in {{ checkFile }}.''\n"'
##     - cwd: /root
##     - stateful: True
fixVal_{{ stig_id }}-{{ checkFile }}:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '{{parmName }}=[0-9]*'
    - repl: '{{ parmName }}={{ parmValu }}'

  {%- endif %}
{%- endfor %}
