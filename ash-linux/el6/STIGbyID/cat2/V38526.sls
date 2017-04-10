# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38526
# Rule ID:		sysctl_net_ipv4_conf_all_secure_redirects
# Finding ID:		V-38526
# Version:		RHEL-06-000086
# SCAP Security ID:	CCE-26854-0
# Finding Level:	Medium
#
#     The system must not accept ICMPv4 secure redirect packets on any
#     interface. Accepting "secure" ICMP redirects (from those gateways
#     listed as default gateways) has few legitimate uses. It should be
#     disabled unless it is absolutely required.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stig_id = 'V38526' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.all.secure_redirects' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: '/root'

# Purely infomational - we're going to force the value, any way,
# via 'sysctl.present' since it forces entry in {{ checkFile }}
{%- if salt.sysctl.get(parmName) == '0' %}
sysctl_V{{ stig_id }}-noRedirects:
  cmd.run:
    - name: 'printf "NOTE: In-memory configuration already ignores\n      ICMPv4 secure redirect packets\n"'
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
    - unless: 'grep "{{ parmName }}[    ]=[     ]0" {{ checkFile }}'

setting_V{{ stig_id }}-{{ parmName }}:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '0'
