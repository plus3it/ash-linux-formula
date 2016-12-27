# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38460
# Finding ID:	V-38460
# Version:	RHEL-06-000515
# Finding Level:	Low
#
#     The NFS server must not have the all_squash option enabled. The 
#     "all_squash" option maps all client requests to a single anonymous 
#     uid/gid on the NFS server, negating the ability to track file access 
#     by user ID.
#
#  CCI: CCI-000764
#  NIST SP 800-53 :: IA-2
#  NIST SP 800-53A :: IA-2.1
#  NIST SP 800-53 Revision 4 :: IA-2
#
############################################################

{%- set stigId = 'V38460' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set checkFile = '/etc/exports' %}
{%- set checkPtn = 'all_squash' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('nfs-utils') %}
  {%- if salt.file.search(checkFile, checkPtn) %}
file_{{ stigId }}-onlyOpt:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '\({{ checkPtn }}\)'
    - repl: ''

file_{{ stigId }}-firstOpt:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '\({{ checkPtn }},'
    - repl: '('

file_{{ stigId }}-secondaryOpt:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: ',{{ checkPtn }}'
    - repl: ''
  {%- else %}
cmd_{{ stigId }}-notice:
  cmd.run:
    - name: 'echo "No NFS exports found with {{ checkPtn }} option enabled"'
  {%- endif %}
{%- else %}
cmd_{{ stigId }}-notice:
  cmd.run:
    - name: 'echo "NFS service not installed: security control not relevant"'
{%- endif %}
