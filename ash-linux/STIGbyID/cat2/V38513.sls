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

script_V38513-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38513.sh
    - cwd: '/root'

{%- if salt['file.file_exists']('/etc/sysconfig/iptables') %}
file_V38513-repl:
  file.replace:
    - name: /etc/sysconfig/iptables
    - pattern: 'INPUT ACCEPT .*$'
    - repl: 'INPUT DROP [0:0]'
{%- else %}
iptables_V38513-existing:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - match: state
    - connstate: ESTABLISHED,RELATED

iptables_V38513-sshdSafety:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - dport: 22
    - proto: tcp
  
iptables_V38513-inputDefault:
  module.run:
    - name: 'iptables.set_policy'
    - table: filter
    - chain: INPUT
    - policy: DROP
  
iptables_V38513-saveRunning:
  module.run:
    - name: 'iptables.save'

service_V38513:
  service:
    - name: iptables
    - running
    - enable: True
{%- endif %}
