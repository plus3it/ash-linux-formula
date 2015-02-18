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

{% set stig_id = '38573' %}

include:
  - ash-linux.authconfig

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V{{ stig_id }}.sh

{% set pamFiles = [
    '/etc/pam.d/system-auth-ac',
    '/etc/pam.d/password-auth-ac'
  ]
%}

{% set pamMod = 'pam_faillock.so' %}
{% set lockTO = '900' %}
{% set preAuth =  'auth        required      ' + pamMod + ' preauth silent audit deny=3 unlock_time=' + lockTO %}
{% set authFail = 'auth        [default=die] ' + pamMod + ' authfail deny=3 unlock_time=' + lockTO + ' fail_interval=900' %}
{% set authSucc = 'auth        required      ' + pamMod + ' authsucc deny=3 unlock_time=' + lockTO + ' fail_interval=900' %}

# Iterate files to alter...
{% for checkFile in pamFiles %}

  {% if salt['file.search'](checkFile, pamMod) %}
notify_V{{ stig_id }}-{{ checkFile }}_exists:
  cmd.run:
    - name: 'printf "{{ pamMod }} already present in {{ checkFile }}\nSee remediation-note that follows for further caveats\n"'
    
    {% if not salt['file.search'](checkFile, preAuth) %}
notify_V{{ stig_id }}-{{ checkFile }}_noPreauth:
  cmd.run:
    - name: 'printf "** Note **\n
The following PAM directive:\n\n{{ preAuth }}\n\n
is missing in {{ checkFile }} file. The targeted\n
security-behavior is probably not present.\n"'
    {% endif %}

  {% else %}
notify_V{{ stig_id }}-{{ checkFile }}_exists:
  cmd.run:
    - name: 'echo "{{ pamMod }} absent in {{ checkFile }}"'

insert_V{{ stig_id }}-{{ checkFile }}_faillock:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^(?P<srctok>auth[ 	]*[a-z]*[ 	]*pam_unix.so.*$)'
    - repl: '{{ preAuth }}\n\g<srctok>\n{{ authFail }}\n{{ authSucc }}'

notify_V{{ stig_id }}-{{ checkFile }}_deviance:
  cmd.run:
    - name: 'echo "STIG prescribes indefinite-lock; utility implements {{ lockTO }}s lock"'
  {% endif %}

{% endfor %}

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
