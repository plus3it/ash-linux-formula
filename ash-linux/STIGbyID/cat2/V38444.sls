# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38444
# Finding ID:	V-38444
# Version:	RHEL-06-000523
# Finding Level:	Medium
#
#     In "ip6tables" the default policy is applied only after all the 
#     applicable rules in the table are examined for a match. Setting 
#     the default policy to "DROP" implements proper design for a 
#     firewall, i.e., any packets which are not explicitly permitted 
#     should not be accepted. 
#
#  CCI: CCI-000066
#  NIST SP 800-53 :: AC-17 e
#  NIST SP 800-53A :: AC-17.1 (v)
#
############################################################

script_V38444-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38444.sh

# Check if IPv6 is enabled
{% set ipv6Value =  salt['sysctl.get']('net.ipv6.conf.all.disable_ipv6') %}
{% if 'unknown' in ipv6Value %}
notify_V38444-sysctl:
  cmd.run:
    - name: 'echo "Notice: IPv6 Is disabled: cannot update ip6tables"'
{% else %}
notify_V38444-sysctl:
  cmd.run:
    - name: 'echo "Info: Updating in-memory ip6tables configuration."'

cmd_V38444-iptablesSet:
  iptables.set_policy:
    - table: filter
    - chain: INPUT
    - policy: DROP
    - family: ipv6

notify_V38444-iptablesSave:
  cmd.run:
    - name: 'echo "Info: Saving in-memory ip6tables configuration to disk."'

iptables_V38444-iptablesSave:
  module.run:
    - name: 'iptables.save'
    - family: 'ipv6'
{% endif %}
