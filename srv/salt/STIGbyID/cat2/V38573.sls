# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38573
# Finding ID:	V-38573
# Version:	RHEL-06-000061
# Finding Level:	Medium
#
#     The system must disable accounts after three consecutive unsuccessful 
#     login attempts. Locking out user accounts after a number of incorrect 
#     attempts prevents direct password guessing attacks.
#
############################################################

script_V38573-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38573.sh

#################################################
## Consult cat3/V38482.sls for handling-method ##
#################################################

{% set pamFiles = [
	'/etc/pam.d/system-auth-ac',
	'/etc/pam.d/password-auth-ac'
  ]
%}


{% for checkFile in pamFiles %}
  {% set pamMod = 'pam_faillock.so' %}
  {% set authFail = 'auth        [default=die] ' + pamMod + ' authfail deny=3 unlock_time=604800 fail_interval=900' %}
  {% set authSucc = 'auth        required      ' + pamMod + ' authsucc deny=3 unlock_time=604800 fail_interval=900' %}

  {% if not salt['file.file_exists'](checkFile) %}
cmd_V38573-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
  {% endif %}


  {% if salt['file.search'](checkFile, pamMod) %}
notify_V38573-{{ checkFile }}_exists:
  cmd.run:
  - name: 'echo "{{ pamMod }} already present in {{ checkFile }}"'
  {% else %}
notify_V38573-{{ checkFile }}_exists:
  cmd.run:
  - name: 'echo "{{ pamMod }} absent in {{ checkFile }}"'

insert_V38573-{{ checkFile }}_faillock:
  file.replace:
  - name: {{ checkFile }}
  - pattern: '^(?P<srctok>auth[ 	]*[a-z]*[ 	]*pam_unix.so.*$)'
  - repl: '\g<srctok>\n{{ authFail }}\n{{ authSucc }}'
  {% endif %}
{% endfor %}
