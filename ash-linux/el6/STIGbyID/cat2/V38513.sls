# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38513
# Finding ID:	V-38513
# Version:	RHEL-06-000120
# Finding Level:	Medium
#
#     The systems local IPv4 firewall must implement a deny-all,
#     allow-by-exception policy for inbound packets. In "iptables" the
#     default policy is applied only after all the applicable rules in the
#     table are examined for a match. Setting the default policy to "DROP"
#     implements proper design for a firewall, ...
#
#  CCI: CCI-000066
#  NIST SP 800-53 :: AC-17 e
#  NIST SP 800-53A :: AC-17.1 (v)
#
############################################################

{%- set stig_id = '38513' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set file = '/etc/sysconfig/iptables' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

V{{stig_id}}-create ash chain:
  iptables.chain_present:
    - name: ASH
    - table: filter
    - family: ipv4

V{{stig_id}}-jump input to ash chain:
  iptables.append:
    - table: filter
    - family: ipv4
    - chain: INPUT
    - jump: ASH
    - save: true
    - require:
      - iptables: V{{stig_id}}-create ash chain

V{{stig_id}}-allow established in input chain:
  iptables.insert:
    - position: 1
    - table: filter
    - family: ipv4
    - chain: INPUT
    - jump: ACCEPT
    - match: state
    - connstate: ESTABLISHED,RELATED
    - save: true
    - onchanges:
      - iptables: V{{stig_id}}-jump input to ash chain
    - require_in:
      - iptables: V{{stig_id}}-set input to drop

V{{stig_id}}-allow ssh in ash chain:
  iptables.append:
    - table: filter
    - family: ipv4
    - chain: ASH
    - jump: ACCEPT
    - dport: 22
    - proto: tcp
    - save: true
    - onchanges:
      - iptables: V{{stig_id}}-jump input to ash chain
    - require_in:
      - iptables: V{{stig_id}}-set input to drop

V{{stig_id}}-allow lo in input chain:
  iptables.append:
    - table: filter
    - family: ipv4
    - chain: INPUT
    - jump: ACCEPT
    - in-interface: lo
    - save: true
    - require_in:
      - iptables: V{{stig_id}}-set input to drop

V{{stig_id}}-set input to drop:
  iptables.set_policy:
    - chain: INPUT
    - policy: DROP
    - save: true
    - require:
      - iptables: V{{stig_id}}-jump input to ash chain

V{{stig_id}}-service running:
  service.running:
    - name: iptables
    - enable: True
    - require:
      - iptables: V{{stig_id}}-set input to drop
