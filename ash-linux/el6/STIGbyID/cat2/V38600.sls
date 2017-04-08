# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38600
# Rule ID:              sysctl_net_ipv4_conf_default_send_redirects
# Finding ID:		V-38600
# Version:		RHEL-06-000080
# SCAP Security ID:	CCE-27001-7
# Finding Level:	Medium
#
#     The system must not send ICMPv4 redirects by default. Sending ICMP
#     redirects permits the system to instruct other systems to update
#     their routing information. The ability to send ICMP redirects is only
#     appropriate for routers.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53 :: CM-6.1 (iv)
#  NIST SP 800-53 :: CM-6 b
#
############################################################

{%- set stig_id = '38600' %}
{%- set scapId = 'CCE-27001-7' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.default.send_redirects' %}

script_V38600-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ 38600 }}.sh
    - cwd: '/root'

# Purely infomational - we're going to force the value, any way,
# via 'sysctl.present' since it forces entry in {{ checkFile }}
{%- if salt.sysctl.get(parmName) == '0' %}
sysctl_V{{ stig_id }}-noRedirects:
  cmd.run:
    - name: 'printf "NOTE: In-memory configuration already disables\n      sending of ICMPv4 redirect packets\n"'
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
