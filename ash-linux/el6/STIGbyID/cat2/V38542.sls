# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38542
# Rule ID:		sysctl_net_ipv4_conf_all_rp_filter
# Finding ID:		V-38542
# Version:		RHEL-06-000096
# SCAP Security ID:	CCE-26979-5
# Finding Level:	Medium
#
#     The system must use a reverse-path filter for IPv4 network traffic
#     when possible on all interfaces. Enabling reverse path filtering
#     drops packets with source addresses that should not have been able to
#     be received on the interface they were received on. It should not be
#     used on systems which are ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stig_id = 'V38542' %}
{%- set scapId = 'CCE-26979-5' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.all.rp_filter' %}
{%- set parmVal = '1' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Purely infomational - we're going to force the value, any way,
# via 'sysctl.present' since it forces entry in {{ checkFile }}
{%- if salt.sysctl.get(parmName) == parmVal %}
sysctl_{{ stig_id }}-noRedirects:
  cmd.run:
    - name: 'printf "NOTE: In-memory configuration already enables\n      reverse path-filtering on all interfaces\n"'
{%- endif %}

# This should *NEVER* be needed on a normal system
create_{{ stig_id }}-{{ checkFile }}:
  file.managed:
    - name: '{{ checkFile }}'
    - replace: False
    - onlyif: 'test -f {{ checkFile }}'

# Need to run the next two because security scanners often
# don't understand "secure by default" settings
comment_{{ stig_id }}-{{ parmName }}:
  file.append:
    - name: '{{ checkFile }}'
    - text: '# Added {{ parmName }} define per STIG-ID: {{ stig_id }}'
    - unless: 'grep "{{ parmName }}[    ]=[     ]{{ parmVal }}" {{ checkFile }}'

setting_{{ stig_id }}-{{ parmName }}:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '{{ parmVal }}'
