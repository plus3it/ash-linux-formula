# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38549
# Finding ID:	V-38549
# Version:	RHEL-06-000103
# Finding Level:	Medium
#
#     The system must employ a local IPv6 firewall. The "ip6tables" service 
#     provides the system's host-based firewalling capability for IPv6 and 
#     ICMPv6.
#
#  CCI: CCI-001118
#  NIST SP 800-53 :: SC-7 (12)
#  NIST SP 800-53A :: SC-7 (12).1
#
############################################################

{%- set stigId = 'V38549' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

service_{{ stigId }}:
  service:
    - name: ip6tables
    - running
    - enable: True
    - onlyif:
      - test -f '/proc/net/if_inet6'
