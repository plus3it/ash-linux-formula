# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38533
# Finding ID:	V-38533
# Version:	RHEL-06-000091
# Finding Level:	Low
#
#     The system must ignore ICMPv4 redirect messages by default. This 
#     feature of the IPv4 protocol has few legitimate uses. It should be 
#     disabled unless it is absolutely required.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38533' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set parmName = 'net.ipv4.conf.default.accept_redirects' %}
{%- set parmVal = '0' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.sysctl.get(parmName) == parmVal %}
sysctl_{{ stigId }}-noRedirects:
  cmd.run:
    - name: 'echo "System already configured to ignore ICMPv4 redirect messages"'
{%- else %}
sysctl_{{ stigId }}-noRedirects:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '{{ parmVal }}'
{%- endif %}
