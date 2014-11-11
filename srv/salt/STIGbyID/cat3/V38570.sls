# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38570
# Finding ID:	V-38570
# Version:	RHEL-06-000058
# Finding Level:	Low
#
#     The system must require passwords to contain at least one special 
#     character. Requiring a minimum number of special characters makes 
#     password guessing attacks more difficult by ensuring a larger search 
#     space.
#
############################################################

script_V38570-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38570.sh

{% if not salt['file.file_exists']('/etc/pam.d/system-auth-ac') %}
cmd-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search']('/etc/pam.d/system-auth-ac', ' pam_cracklib.so ') %}
  {% if salt['file.search']('/etc/pam.d/system-auth-ac', ' ocredit=[0-9][0-9]*[ ]*') %}
# Change existing ocredit with positive integer value to minus-1
ocredit_V38570-minusOne:
  file.replace:
  - name: /etc/pam.d/system-auth-ac
  - pattern: 'ocredit=[0-9][0-9]*'
  - repl: 'ocredit=-1'
  {% elif salt['file.search']('/etc/pam.d/system-auth-ac', ' ocredit=-[0-9][0-9]*[ ]*') %}
ocredit_V38570-minusOne:
  cmd.run:
  - name: 'echo "Passwords already require at least one digit"'
  {% else %}
# Tack on decredit of minus-1 if necessary
ocredit_V38570-minusOne:
  file.replace:
  - name: '/etc/pam.d/system-auth-ac'
  - pattern: '^(?P<srctok>password[ 	]*requisite[ 	]*pam_cracklib.so.*$)'
  - repl: '\g<srctok> ocredit=-1'
  {% endif %}
{% endif %}


