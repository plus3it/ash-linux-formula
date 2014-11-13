# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38571
# Finding ID:	V-38571
# Version:	RHEL-06-000059
# Finding Level:	Low
#
#     The system must require passwords to contain at least one lowercase 
#     alphabetic character. Requiring a minimum number of lowercase 
#     characters makes password guessing attacks more difficult by ensuring 
#     a larger search space.
#
#  CCI: CCI-000193
#  NIST SP 800-53 :: IA-5 (1) (a)
#  NIST SP 800-53A :: IA-5 (1).1 (v)
#  NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
#
############################################################

script_V38571-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38571.sh

{% if not salt['file.file_exists']('/etc/pam.d/system-auth-ac') %}
cmd-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search']('/etc/pam.d/system-auth-ac', ' pam_cracklib.so ') %}
  {% if salt['file.search']('/etc/pam.d/system-auth-ac', ' lcredit=[0-9][0-9]*[ ]*') %}
# Change existing lcredit with positive integer value to minus-1
lcredit_V38571-minusOne:
  file.replace:
  - name: /etc/pam.d/system-auth-ac
  - pattern: 'lcredit=[0-9][0-9]*'
  - repl: 'lcredit=-1'
  {% elif salt['file.search']('/etc/pam.d/system-auth-ac', ' lcredit=-[0-9][0-9]*[ ]*') %}
lcredit_V38571-minusOne:
  cmd.run:
  - name: 'echo "Passwords already require at least one digit"'
  {% else %}
# Tack on decredit of minus-1 if necessary
lcredit_V38571-minusOne:
  file.replace:
  - name: '/etc/pam.d/system-auth-ac'
  - pattern: '^(?P<srctok>password[ 	]*requisite[ 	]*pam_cracklib.so.*$)'
  - repl: '\g<srctok> lcredit=-1'
  {% endif %}
{% endif %}


