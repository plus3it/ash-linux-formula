# STIG URL:
# Finding ID:	RHEL-07-040320
# Version:	RHEL-07-040320_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     For systems using DNS resolution, at least two name servers must 
#     be configured.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040320' %}
{%- set helperLoc = 'ash-linux/STIGbyID/el7/cat3/files' %}
{%- set chkCfg = '/etc/nsswitch.conf' %}
{%- set resCfg = '/etc/resolv.conf' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# What to do if resolver uses DNS
{%- if salt['file.search'](chkCfg, '^hosts:.*dns') %}
null_{{ stig_id }}-resolvConf:
  cmd.run:
    - name: 'echo "{{ chkCfg }} configured for DNS"'
  # Message to throw if resolver is DHCP-configured
  {%- if salt['file.search'](resCfg, 'dhclient-script') %}
servlist_{{ stig_id }}-resolvConf:
  cmd.run:
    - name: 'echo "{{ resCfg }} managed via DHCP"'
  # Message to throw if resolver is hard-configured with too-few DNS servers
  {%- elif not salt['file.search'](resCfg, '^nameserver.*\n^nameserver') %}
servlist_{{ stig_id }}-resolvConf:
  cmd.run:
    - name: 'echo "Insufficient number of nameservers defined in {{ resCfg }}." > /dev/stderr && exit 1'
  {%- endif %}
# What to do if resolver doesn't use DNS
{%- else %}
null_{{ stig_id }}-resolvConf:
  file.comment:
    - name: '{{ resCfg }}'
    - regex: '^nameserver'
{%- endif %}
