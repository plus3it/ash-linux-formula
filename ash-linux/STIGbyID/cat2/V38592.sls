# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38592
# Finding ID:	V-38592
# Version:	RHEL-06-000356
# Finding Level:	Medium
#
#     The system must require administrator action to unlock an account 
#     locked by excessive failed login attempts. Locking out user accounts 
#     after a number of incorrect attempts prevents direct password 
#     guessing attacks. Ensuring that an administrator is involved in 
#     unlocking locked accounts draws appropriate ...
#
#  CCI: CCI-000047
#  NIST SP 800-53 :: AC-7 b
#  NIST SP 800-53A :: AC-7.1 (iv)
#
############################################################

script_V38592-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38592.sh

#################################################
## Consult cat3/V38482.sls for handling-method ##
#################################################

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

# Ensure that authconfig has been run prior to trying to update the PAM files
cmd_V38592-linkSysauth:
  cmd.run:
    - name: '/usr/sbin/authconfig --update'
    - unless: 'test -f /etc/pam.d/system-auth-ac'

# Iterate files to alter...
{% for checkFile in pamFiles %}

  {% if salt['file.search'](checkFile, pamMod) %}
notify_V38592-{{ checkFile }}_exists:
  cmd.run:
    - name: 'printf "{{ pamMod }} already present in {{ checkFile }}\nSee remediation-note that follows for further caveats\n"'
    {% if not salt['file.search'](checkFile, preAuth) %}
notify_V38592-{{ checkFile }}_noPreauth:
  cmd.run:
    - name: 'printf "** Note **\n
The following PAM directive:\n\n{{ preAuth }}\n\n
is missing in {{ checkFile }} file. The targeted\n
security-behavior is probably not present.\n"'
    {% endif %}
  {% else %}
notify_V38592-{{ checkFile }}_exists:
  cmd.run:
    - name: 'echo "{{ pamMod }} absent in {{ checkFile }}"'

insert_V38592-{{ checkFile }}_faillock:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^(?P<srctok>auth[ 	]*[a-z]*[ 	]*pam_unix.so.*$)'
    - repl: '{{ preAuth }}\n\g<srctok>\n{{ authFail }}\n{{ authSucc }}'
  {% endif %}
{% endfor %}

notify_V38592-docError:
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
