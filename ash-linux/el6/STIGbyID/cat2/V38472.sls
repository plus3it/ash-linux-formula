# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38472
# Finding ID:	V-38472
# Version:	RHEL-06-000048
# Finding Level:	Medium
#
#     All system command files must be owned by root. System binaries are 
#     executed by privileged users as well as system services, and 
#     restrictive permissions are necessary to ensure that their execution 
#     of these programs cannot be co-opted.
#
#  CCI: CCI-001499
#  NIST SP 800-53 :: CM-5 (6)
#  NIST SP 800-53A :: CM-5 (6).1
#  NIST SP 800-53 Revision 4 :: CM-5 (6)
#
############################################################

{%- set stigId = 'V38472' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set dirList = [ '/bin', '/usr/bin', '/sbin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin', ] %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- for chkDir in dirList %}
file_{{ stigId }}-{{ chkDir }}:
  file.directory:
    - name: '{{ chkDir }}'
    - user: root
    - recurse:
      - user
{%- endfor %}
