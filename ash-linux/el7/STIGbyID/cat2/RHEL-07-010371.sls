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
{%- set parmValue = salt.pillar.get('ash-linux:lookup:faillock:' + parmName, '900') %}
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
  {%- if salt.file.is_link(checkFile) %}
    {%- set checkFile = checkFile + '-ac' %}
  {%- endif %}

  {%- if not salt.file.file_exists(checkFile) %}

#file did not exist when jinja templated the file; file will be configured 
#by authconfig.sls in the include statement. 
#Use macro to add necessary rules
{{ pammod_template(stig_id, checkFile, pamMod, preAuth, authFail, authSucc) }}

  {%- elif not salt.file.search(checkFile, pamMod) %}

#file {{ checkFile }} exists
#{{ pamMod }} not yet present in file
#Use macro to add necessary rules
{{ pammod_template(stig_id, checkFile, pamMod, preAuth, authFail, authSucc) }}

  {%- elif not salt.file.search(checkFile, preAuth) %}

#file {{ checkFile }} exists
#{{ pamMod }} present in file
#missing preAuth check; notify but do not modify
notify_{{ stig_id }}-{{ checkFile }}_noPreauth:
  cmd.run:
    - name: 'printf "** Note **\n
TL;DR: Manual inspection and remediation will be \n
required to determine whether the PAM directive \n
is configured properly per the system''s \n
requirements. \n\n
The PAM module {{ pamMod }} has been configured\n
on this system, but is not currently using the \n
prescribed PAM directive:\n\n{{ preAuth }}\n\n
This means another mechanism (other than this \n
utility) has configured this directive. To avoid \n
overwriting what may have been desired behavior \n
this utility will not modify this directive. \n
However, the security-behavior required by the \n
STIG is probably not present. "'

  {%- else %}

#file {{ checkFile }} exists
#module {{ pamMod }} already present in file
#preAuth rule already present in file
notify_{{ stig_id }}-{{ checkFile }}_exists:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ pamMod }} already present in {{ checkFile }} with correct ruleset.''\n"'
    - cwd: /root
    - stateful: True

  {%- endif %}
{%- endfor %}
