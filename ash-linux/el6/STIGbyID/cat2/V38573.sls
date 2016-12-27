# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38573
# Finding ID:	V-38573
# Version:	RHEL-06-000061
# Finding Level:	Medium
#
#     The system must disable accounts after three consecutive unsuccessful 
#     login attempts. Locking out user accounts after a number of incorrect 
#     attempts prevents direct password guessing attacks.
#
#  CCI: CCI-000044
#  NIST SP 800-53 :: AC-7 a
#  NIST SP 800-53A :: AC-7.1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-7 a
#
############################################################

include:
  - ash-linux.authconfig

{%- set stig_id = '38573' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

{%- set pamFiles = [
    '/etc/pam.d/system-auth-ac',
    '/etc/pam.d/password-auth-ac'
  ]
%}

{%- set pamMod = 'pam_faillock.so' %}
{%- set lockTO = '900' %}
{%- set preAuth =  'auth        required      ' + pamMod + ' preauth silent audit deny=3 unlock_time=' + lockTO %}
{%- set authFail = 'auth        [default=die] ' + pamMod + ' authfail deny=3 unlock_time=' + lockTO + ' fail_interval=900' %}
{%- set authSucc = 'auth        required      ' + pamMod + ' authsucc deny=3 unlock_time=' + lockTO + ' fail_interval=900' %}

#define macro to configure the pam module in a file
{%- macro pammod_template(stig_id, file, pam_module, preauth, authfail, authsucc, lock_timeout) %}
notify_V{{ stig_id }}-{{ file }}_exists:
  cmd.run:
    - name: 'echo "{{ pam_module }} was absent in {{ file }}"'

insert_V{{ stig_id }}-{{ file }}_faillock:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<srctok>auth[ \t]*[a-z]*[ \t]*pam_unix.so.*$)'
    - repl: '{{ preauth }}\n\g<srctok>\n{{ authfail }}\n{{ authsucc }}'
    - onlyif:
      - 'test $(grep -c -E -e "{{ pam_module }}" {{ file }}) -eq 0'

notify_V{{ stig_id }}-{{ file }}_deviance:
  cmd.run:
    - name: 'echo "STIG prescribes indefinite-lock; utility implements {{ lock_timeout }}s lock"'
{%- endmacro %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

# Iterate files to alter...
{%- for checkFile in pamFiles %}

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
notify_V{{ stig_id }}-{{ checkFile }}_noPreauth:
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
notify_V{{ stig_id }}-{{ checkFile }}_exists:
  cmd.run:
    - name: 'printf "{{ pamMod }} already present in {{ checkFile }} with correct ruleset."'

  {%- endif %}
{%- endfor %}

notify_V{{ stig_id }}-docError:
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
\tRedHat Solution ID 62949.\n"'
