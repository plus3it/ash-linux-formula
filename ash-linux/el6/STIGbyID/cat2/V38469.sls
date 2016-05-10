# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38469
# Finding ID:	V-38469
# Version:	RHEL-06-000047
# Finding Level:	Medium
#
#     All system command files must have mode 0755 or less permissive. 
#     System binaries are executed by privileged users, as well as system 
#     services, and restrictive permissions are necessary to ensure 
#     execution of these programs cannot be co-opted.
#
#  CCI: CCI-001499
#  NIST SP 800-53 :: CM-5 (6)
#  NIST SP 800-53A :: CM-5 (6).1
#  NIST SP 800-53 Revision 4 :: CM-5 (6)
#
############################################################

{%- set stigId = 'V38469' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

# Define list of binary directories to search
{%- set checkBinDirs = [
	'/bin',
	'/usr/bin',
	'/usr/local/bin',
	'/sbin',
	'/usr/sbin',
	'/usr/local/sbin'
  ]
%}

# Iterate previously-defined list
{%- for binDir in checkBinDirs %}

# Report what we're doing
notify_{{ stigId }}-{{ binDir }}:
  cmd.run:
    - name: 'echo "Checking ''{{ binDir }}'' for group- or world-writable files"'

# Check (and fix as necessary) library
strip_{{ stigId }}-{{ binDir }}:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}-helper.sh
    - cwd: '/root'
    - args: {{ binDir }}

{%- endfor %}
