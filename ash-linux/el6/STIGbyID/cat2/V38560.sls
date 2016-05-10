# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38560
# Finding ID:	V-38560
# Version:	RHEL-06-000116
# Finding Level:	Medium
#
#     The operating system must connect to external networks or information 
#     systems only through managed IPv4 interfaces consisting of boundary 
#     protection devices arranged in accordance with an organizational 
#     security architecture. The "iptables" service provides the system's 
#     host-based firewalling capability for IPv4 and ICMP.
#
#  CCI: CCI-001098
#  NIST SP 800-53 :: SC-7 b
#  NIST SP 800-53A :: SC-7.1 (iv)
#  NIST SP 800-53 Revision 4 :: SC-7 c
#
############################################################

{%- set stig_id = '38560' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

pkg_V{{ stig_id }}:
  pkg.installed:
    - name: iptables

iptables_V{{ stig_id }}-saveRunning:
  module.run:
    - name: 'iptables.save'
    - require:
      - pkg: pkg_V{{ stig_id }}

service_V{{ stig_id }}:
  service.running:
    - name: iptables
    - enable: True
    - require:
      - module: iptables_V{{ stig_id }}-saveRunning
