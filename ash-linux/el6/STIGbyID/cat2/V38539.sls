# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38539
# Finding ID:	V-38539
# Version:	RHEL-06-000095
# Finding Level:	Medium
#
#     The system must be configured to use TCP syncookies. A TCP SYN flood 
#     attack can cause a denial of service by filling a system's TCP 
#     connection table with connections in the SYN_RCVD state. Syncookies 
#     can be used to track a connection when a subsequent ...
#
#  CCI: CCI-001095
#  NIST SP 800-53 :: SC-5 (2)
#  NIST SP 800-53A :: SC-5 (2).1
#  NIST SP 800-53 Revision 4 :: SC-5 (2)
#
############################################################

{%- set stigId = 'V38539' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.tcp_syncookies' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.search(chkFile, parmName) %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} = 1'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ chkFile }}'
    - text:
      - ' '
      - '# Enable TCP SYN-cookies'
      - '{{ parmName }} = 1'
{%- endif %}
