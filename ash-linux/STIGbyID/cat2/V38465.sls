# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38465
# Finding ID:	V-38465
# Version:	RHEL-06-000045
# Finding Level:	Medium
#
#     Library files must have mode 0755 or less permissive. Files from 
#     shared library directories are loaded into the address space of 
#     processes (including privileged ones) or of the kernel itself at 
#     runtime. Restrictive permissions are necessary to protect ...
#
#  CCI: CCI-001499
#  NIST SP 800-53 :: CM-5 (6)
#  NIST SP 800-53A :: CM-5 (6).1
#  NIST SP 800-53 Revision 4 :: CM-5 (6)
#
############################################################

script_V38465-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38465.sh

# Define list of library directories to search
{% set checkLibDirs = [
	'/lib',
	'/lib64',
	'/usr/lib',
	'/usr/lib64'
  ]
%}

# Iterate previously-defined list
{% for libDir in checkLibDirs %}

# Report what we're doing
notify_V38465-{{ libDir }}:
  cmd.run:
    - name: 'echo "Checking ''{{ libDir }}'' for group- or world-writable files"'

# Check (and fix as necessary) library
strip_V38465-{{ libDir }}:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38465-helper.sh
    - args: {{ libDir }}

{% endfor %}
