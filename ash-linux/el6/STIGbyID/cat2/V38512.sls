# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38512
# Finding ID:	V-38512
# Version:	RHEL-06-000117
# Finding Level:	Medium
#
#     The operating system must prevent public IPv4 access into an
#     organizations internal networks, except as appropriately mediated by
#     managed interfaces employing boundary protection devices. The
#     "iptables" service provides the system's host-based firewalling
#     capability for IPv4 and ICMP.
#
#  CCI: CCI-001100
#  NIST SP 800-53 :: SC-7 (2)
#  NIST SP 800-53A :: SC-7 (2).1 (ii)
#
############################################################

{%- set stig_id = '38512' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

pkg_V{{ stig_id }}:
  pkg.installed:
    - name: iptables

iptables_V{{ stig_id }}-listRules:
  cmd.run:
    - name: 'iptables --list'
    - require:
      - pkg: pkg_V{{ stig_id }}

iptables_V{{ stig_id }}-saveRunning:
  module.run:
    - name: 'iptables.save'
    - require:
      - cmd: iptables_V{{ stig_id }}-listRules

service_V{{ stig_id }}:
  service.running:
    - name: iptables
    - enable: True
    - require:
      - module: iptables_V{{ stig_id }}-saveRunning
