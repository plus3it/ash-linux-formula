# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38544
# Finding ID:	V-38544
# Version:	RHEL-06-000097
# Finding Level:	Medium
#
#     The system must use a reverse-path filter for IPv4 network traffic 
#     when possible by default. Enabling reverse path filtering drops 
#     packets with source addresses that should not have been able to be 
#     received on the interface they were received on. It should not be 
#     used on systems which are ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################
{%- set stigId = 'V38544' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.default.rp_filter' %}

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
      - '# Enable reverse-path filtering (per STIG V-38544)'
      - '{{ parmName }} = 1'
{%- endif %}
