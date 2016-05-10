# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38553
# Finding ID:	V-38553
# Version:	RHEL-06-000107
# Finding Level:	Medium
#
#     The operating system must prevent public IPv6 access into an 
#     organizations internal networks, except as appropriately mediated by 
#     managed interfaces employing boundary protection devices. The 
#     "ip6tables" service provides the system's host-based firewalling 
#     capability for IPv6 and ICMPv6.
#
#  CCI: CCI-001100
#  NIST SP 800-53 :: SC-7 (2)
#  NIST SP 800-53 :: SC-7 (2).1 (ii)
#
############################################################
{%- set stigId = 'V38553' %}
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
