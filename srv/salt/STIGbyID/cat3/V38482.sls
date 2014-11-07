# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38482
# Finding ID:	V-38482
# Version:	RHEL-06-000056
# Finding Level:	Low
#
#     The system must require passwords to contain at least one numeric 
#     character. Requiring digits makes password guessing attacks more 
#     difficult by ensuring a larger search space.
#
############################################################

script_V38482-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38482.sh

{% if not salt['file.file_exists']('/etc/pam.d/system-auth-ac') %}
cmd-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search']('/etc/pam.d/system-auth-ac', ' pam_cracklib.so ') %}
  {% if salt['file.search']('/etc/pam.d/system-auth-ac', ' dcredit=[0-9][0-9]*[ ]*') %}
# Change existing dcredit with positive integer value to minus-1
dcredit_V38482-minusOneA:
  file.replace:
  - name: /etc/pam.d/system-auth-ac
  - pattern: 'dcredit=[0-9][0-9]*'
  - repl: 'dcredit=-1'
  {% elif salt['file.search']('/etc/pam.d/system-auth-ac', ' dcredit=-[0-9][0-9]*[ ]*') %}
dcredit_V38482-minusOneB:
  cmd.run:
  - name: 'echo "Passwords already require at least one digit"'
  {% else %}
# Tack on decredit of minus-1 if necessary
################################
## THIS ONE ISN'T WORKING YET ##
################################
dcredit_V38482-minusOneC:
  file.replace:
  - name: '/etc/pam.d/system-auth-ac'
  - pattern: '^(?P<srctok>password[ 	]requisite[ 	]pam_cracklib.so.*$)'
  - repl: '\g<srctok> dcredit=-1'
  {% endif %}
{% endif %}


