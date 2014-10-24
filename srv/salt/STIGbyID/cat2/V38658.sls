# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38658
# Finding ID:	V-38658
# Version:	RHEL-06-000274
# Finding Level:	Medium
#
#     The system must prohibit the reuse of passwords within twenty-four 
#     iterations. Preventing reuse of previous passwords helps ensure that 
#     a compromised password is not reused by a user.
#
############################################################

script_V38658-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38658.sh

{% if salt['file.search']('/etc/pam.d/system-auth-ac', 'password[ 	]*sufficient[ 	]*pam_unix.so') and not salt['file.search']('/etc/pam.d/system-auth-ac', 'password[ 	]*sufficient[ 	]*pam_unix.so.*remember=24') %}
file_V38658-repl:
  file.replace:
  - name: '/etc/pam.d/system-auth-ac'
  - pattern: '^(?P<srctok>password[ 	]*sufficient[ 	]*pam_unix.so.*$)'
  - repl: '\g<srctok> remember=24'
{% else %}
status_V38658-reuseParm:
  cmd.run:
  - name: 'echo "Re-use parameter already set"'
{% endif %}

link_v38658:
  file.symlink:
  - name: '/etc/pam.d/system-auth'
  - target: '/etc/pam.d/system-auth-ac'
