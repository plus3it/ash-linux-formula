# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38524
# Rule ID:		sysctl_net_ipv4_conf_all_accept_redirects
# Finding ID:		V-38524
# Version:		RHEL-06-000084
# SCAP Security ID: 	CCE-27027-2
# Finding Level:	Medium
#
#     The system must not accept ICMPv4 redirect packets on any interface.
#     Accepting ICMP redirects has few legitimate uses. It should be
#     disabled unless it is absolutely required.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stig_id = 'V38524' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.all.accept_redirects' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: '/root'

# Purely infomational - we're going to force the value, any way,
# via 'sysctl.present' since it forces entry in {{ checkFile }}
{%- if salt.sysctl.get(parmName) == '0' %}
sysctl_V{{ stig_id }}-noRedirects:
  cmd.run:
    - name: 'printf "NOTE: In-memory configuration already disables\n      sending of ICMPv4 redirects for all interfaces\n"'
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
    - text: '# Added {{ parmName }} define per STIG-ID: {{ stig_id }}'
    - unless: 'grep "{{ parmName }}[    ]=[     ]0" {{ checkFile }}'

setting_V{{ stig_id }}-{{ parmName }}:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '0'
