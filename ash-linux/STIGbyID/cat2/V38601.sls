# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38601
# Rule ID:		sysctl_ipv4_all_send_redirects
# Finding ID:		V-38601
# Version:		RHEL-06-000081
# SCAP Security ID:	CCE-27004-1
# Finding Level:	Medium
#
#     The system must not send ICMPv4 redirects from any interface. Sending 
#     ICMP redirects permits the system to instruct other systems to update 
#     their routing information. The ability to send ICMP redirects is only 
#     appropriate for routers.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53 :: CM-6.1 (iv)
#  NIST SP 800-53 :: CM-6 b
#
############################################################

{% set stig_id = 'V38601' %}
{% set scapId = 'CCE-27004-1' %}
{%- set helperLoc = 'ash-linux/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.all.send_redirects' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: '/root'

{% if salt['file.search']('/etc/sysctl.conf', parmName)
 %}
file_{{ stig_id }}-repl:
  file.replace:
    - name: '/etc/sysctl.conf'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} = 0'
{% else %}
file_{{ stig_id }}-append:
  file.append:
    - name: '/etc/sysctl.conf'
    - text:
      - ' '
      - '# Disable sending ICMP redirects (per STIG V-38601)'
      - '{{ parmName }} = 0'
{% endif %}

