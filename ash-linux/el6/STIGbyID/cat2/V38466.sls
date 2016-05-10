# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38466
# Finding ID:	V-38466
# Version:	RHEL-06-000046
# Finding Level:	Medium
#
#     Library files must be owned by root. Files from shared library 
#     directories are loaded into the address space of processes (including 
#     privileged ones) or of the kernel itself at runtime. Proper ownership 
#     is necessary to protect the ...
#
#  CCI: CCI-001499
#  NIST SP 800-53 :: CM-5 (6)
#  NIST SP 800-53A :: CM-5 (6).1
#  NIST SP 800-53 Revision 4 :: CM-5 (6)
#
############################################################

{%- set stigId = 'V38466' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set dirList = [ '/lib', '/lib64', '/usr/lib', '/usr/lib64', ] %}

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
