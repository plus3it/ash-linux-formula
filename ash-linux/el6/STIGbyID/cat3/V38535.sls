# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38535
# Rule ID:		sysctl_net_ipv4_icmp_echo_ignore_broadcasts
# Finding ID:		V-38535
# Version:		RHEL-06-000092
# SCAP Security ID:	CCE-26883-9
# Finding Level:	Low
#
#     The system must not respond to ICMPv4 sent to a broadcast address.
#     Ignoring ICMP echo requests (pings) sent to broadcast or multicast
#     addresses makes the system slightly more difficult to enumerate on
#     the network.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stig_id = '38535' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.icmp_echo_ignore_broadcasts' %}


script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

# Purely infomational - we're going to force the value, any way,
# via 'sysctl.present' since it forces entry in {{ checkFile }}
{%- if salt.sysctl.get('net.ipv4.icmp_echo_ignore_broadcasts') == '1' %}
sysctl_V{{ stig_id }}-noRedirects:
  cmd.run:
    - name: 'printf "NOTE: In-memory configuration already ignores\n      ICMPv4 packets sent to a broadcast address\n"'
{%- endif %}

# This should *NEVER* be needed on a normal system
create_V{{ stig_id }}-{{ checkFile }}:
  file.managed:
    - name: '{{ checkFile }}'
    - replace: False
    - onlyif: 'test -f {{ checkFile }}'

# Need to run the next two because security scanners often
# don't understand "secure by default" settings
comment_V{{ stig_id }}-{{ parmName }}:
  file.append:
    - name: '{{ checkFile }}'
    - text: '# Added {{ parmName }} define per STIG-ID: V-{{ stig_id }}'
    - unless: 'grep "{{ parmName }}[    ]=[     ]1" {{ checkFile }}'

setting_V{{ stig_id }}-{{ parmName }}:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '1'
