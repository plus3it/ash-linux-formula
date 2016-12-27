# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38548
# Finding ID:	V-38548
# Version:	RHEL-06-000099
# Finding Level:	Medium
#
#     The system must ignore ICMPv6 redirects by default. An illicit ICMP 
#     redirect message could result in a man-in-the-middle attack.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38548' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv6.conf.default.accept_redirects' %}

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
      - '# Disable ICMPv6 redirects (per STIG V-38548)'
      - '{{ parmName }} = 0'
{%- endif %}
