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
                    ]
 %}
{%- set pamMod = 'pam_faillock.so' %}
{%- set lockTO = '900' %}
{%- set preAuth =  'auth        required      ' + pamMod + ' preauth silent audit deny=3 unlock_time=' + lockTO %}
{%- set authFail = 'auth        [default=die] ' + pamMod + ' authfail deny=3 unlock_time=' + lockTO + ' fail_interval=900' %}
{%- set authSucc = 'auth        required      ' + pamMod + ' authsucc deny=3 unlock_time=' + lockTO + ' fail_interval=900' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root


#define macro to configure the pam module in a file
{%- macro pammod_template(stig_id, file, pam_module, preauth, authfail, authsucc, lock_timeout) %}
notify_{{ stig_id }}-{{ file }}_exists:
  cmd.run:
    - name: 'echo "{{ pam_module }} was absent in {{ file }}"'

insert_{{ stig_id }}-{{ file }}_faillock:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<srctok>auth[ \t]*[a-z]*[ \t]*pam_unix.so.*$)'
    - repl: '{{ preauth }}\n\g<srctok>\n{{ authfail }}\n{{ authsucc }}'
    - onlyif:
      - 'test $(grep -c -E -e "{{ pam_module }}" {{ file }}) -eq 0'

notify_{{ stig_id }}-{{ file }}_deviance:
  cmd.run:
    - name: 'echo "STIG prescribes indefinite-lock; utility implements {{ lock_timeout }}s lock"'
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
{{ pammod_template(stig_id, checkFile, pamMod, preAuth, authFail, authSucc, lockTO) }}

  {%- elif not salt.file.search(checkFile, pamMod) %}

#file {{ checkFile }} exists
#{{ pamMod }} not yet present in file
#Use macro to add necessary rules
{{ pammod_template(stig_id, checkFile, pamMod, preAuth, authFail, authSucc, lockTO) }}

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
    - name: 'printf "{{ pamMod }} already present in {{ checkFile }} with correct ruleset."'

  {%- endif %}
{%- endfor %}

notify_{{ stig_id }}-docError:
  cmd.run:
    - name: 'printf "
************\n
** NOTICE **\n
************\n
\tIf following STIG/SCAP guidance and only implementing the:\n\n
{{ authFail }}\n
{{ authSucc }}\n\n
\tGuidance, desired lockout behavior will not be achieved.  \n
\tThis tool corrects the STIG-prescribed remediation per\n
\tRedHat Solution ID 62949.\n\n
Additionally: DISA security guidelines (STIGS) prescribe\n
an indefinite-lock/manual-unlock policy; for operational-\n
supportability reasons, this utility implements a {{ lockTO }}s\n
lock. To match STIGs: edit the relevant PAM files and set\n
the ''unlock_time'' value to ''604800''.\n"'
