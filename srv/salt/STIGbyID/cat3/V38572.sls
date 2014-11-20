# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38572
# Finding ID:	V-38572
# Version:	RHEL-06-000060
# Finding Level:	Low
#
#     The system must require at least four characters be changed between 
#     the old and new passwords during a password change. Requiring a 
#     minimum number of different characters during password changes 
#     ensures that newly changed passwords should not resemble previously 
#     compromised ones. Note that passwords which are changed on 
#     compromised systems will still be compromised, however. 
#
#  CCI: CCI-000195
#  NIST SP 800-53 :: IA-5 (1) (b)
#  NIST SP 800-53A :: IA-5 (1).1 (v)
#  NIST SP 800-53 Revision 4 :: IA-5 (1) (b)
#
############################################################

script_V38572-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38572.sh

{% if not salt['file.file_exists']('/etc/pam.d/system-auth-ac') %}
cmd_V38572-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search']('/etc/pam.d/system-auth-ac', ' pam_cracklib.so ') %}
  {% if salt['file.search']('/etc/pam.d/system-auth-ac', ' difok=[0-9][0-9]*[ ]*') %}
# Change existing difok with positive integer value to minus-1
difok_V38572-minusOne:
  file.replace:
  - name: /etc/pam.d/system-auth-ac
  - pattern: 'difok=[0-9][0-9]*'
  - repl: 'difok=-1'
  {% elif salt['file.search']('/etc/pam.d/system-auth-ac', ' difok=-[0-9][0-9]*[ ]*') %}
difok_V38572-minusOne:
  cmd.run:
  - name: 'echo "Passwords already require at least four character differences"'
  {% else %}
# Tack on decredit of minus-1 if necessary
difok_V38572-minusOne:
  file.replace:
  - name: '/etc/pam.d/system-auth-ac'
  - pattern: '^(?P<srctok>password[ 	]*requisite[ 	]*pam_cracklib.so.*$)'
  - repl: '\g<srctok> difok=-1'
  {% endif %}
{% endif %}


