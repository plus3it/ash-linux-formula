# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38686
# Finding ID:	V-38686
# Version:	RHEL-06-000320
# Finding Level:	Medium
#
#     The systems local firewall must implement a deny-all, 
#     allow-by-exception policy for forwarded packets. In "iptables" the 
#     default policy is applied only after all the applicable rules in the 
#     table are examined for a match. Setting the default policy to "DROP" 
#     implements proper design for a firewall, ...
#
#  CCI: CCI-001109
#  NIST SP 800-53 :: SC-7 (5)
#  NIST SP 800-53A :: SC-7 (5).1 (i) (ii)
#  NIST SP 800-53 Revision 4 :: SC-7 (5)
#
############################################################

script_V38686-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38686.sh
    - cwd: '/root'

{% if salt['file.file_exists']('/etc/sysconfig/iptables') %}
file_V38686-repl:
  file.replace:
    - name: /etc/sysconfig/iptables
    - pattern: 'FORWARD ACCEPT .*$'
    - repl: 'FORWARD DROP [0:0]'
{% else %}
iptables_V38686-forwardDefault:
  module.run:
    - name: 'iptables.set_policy'
    - table: filter
    - chain: INPUT
    - policy: DROP
  
iptables_V38686-saveRunning:
  module.run:
    - name: 'iptables.save'

service_V38686:
  service:
    - name: iptables
    - running
    - enable: True
{% endif %}
