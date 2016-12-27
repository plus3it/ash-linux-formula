# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38529
# Finding ID:	V-38529
# Version:	RHEL-06-000089
# Finding Level:	Medium
#
#     The system must not accept IPv4 source-routed packets by default. 
#     Accepting source-routed packets in the IPv4 protocol has few 
#     legitimate uses. It should be disabled unless it is absolutely 
#     required.
#
#  CCI: CI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################
{%- set stigId = 'V38529' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.default.accept_source_route' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.search(chkFile, parmName) %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} = 0'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ chkFile }}'
    - text:
      - ' '
      - '# Disable ICMPv4 secure redirect packtes'
      - '{{ parmName }} = 0'
{%- endif %}
