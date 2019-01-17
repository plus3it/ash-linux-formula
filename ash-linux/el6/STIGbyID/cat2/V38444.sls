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

{%- set stig_id = '38444' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

# Check if IPv6 is enabled
{%- set ipv6_check = salt['file.file_exists']('/proc/net/if_inet6') %}
{%- if not ipv6_check %}
notify_V{{ stig_id }}-sysctl:
  cmd.run:
    - name: 'echo "Notice: IPv6 Is disabled: cannot update ip6tables"'
{%- else %}
notify_V{{ stig_id }}-sysctl:
  cmd.run:
    - name: 'echo "Info: Updating in-memory ip6tables configuration."'

cmd_V{{ stig_id }}-iptablesSet:
  iptables.set_policy:
    - table: filter
    - chain: INPUT
    - policy: DROP
    - family: ipv6
    - check_cmd:
      - test -f '/proc/net/if_inet6'

notify_V{{ stig_id }}-iptablesSave:
  cmd.run:
    - name: 'echo "Info: Saving in-memory ip6tables configuration to disk."'
    - require:
      - iptables: cmd_V{{ stig_id }}-iptablesSet

iptables_V{{ stig_id }}-iptablesSave:
  module.run:
    - name: 'iptables.save'
    - family: 'ipv6'
    - require:
      - iptables: cmd_V{{ stig_id }}-iptablesSet
{%- endif %}
