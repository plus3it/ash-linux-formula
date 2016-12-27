# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38523
# Finding ID:	V-38523
# Version:	RHEL-06-000083
# Finding Level:	Medium
#
#     The system must not accept IPv4 source-routed packets on any 
#     interface. Accepting source-routed packets in the IPv4 protocol has 
#     few legitimate uses. It should be disabled unless it is absolutely 
#     required.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38523' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.all.accept_source_route' %}
{%- set parmVal = '0' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

# Purely informational - we're going to force the value, any way,
# via 'sysctl.present' since it forces entry in {{ cfgFile }}
{%- if salt.sysctl.get(parmName) == parmVal %}
sysctl_{{ stigId }}-inMemCheck:
  cmd.run:
    - name: 'printf "**************************************************\n* NOTE: In-memory configuration already disables *\n*       accepting source-routed packet requests  *\n**************************************************\n"'
{%- endif %}

# Next two needed because some security scanners do not understand
# "secure by default" sysctl settings
comment_{{ stigId }}-{{ parmName }}:
  file.append:
    - name: '{{ cfgFile }}'
    - text: '# Added {{ parmName }} (per STIG-ID {{ stigId }})'
    - unless: 'grep "{{ parmName }}[	 ]=[	 ]{{ parmVal }}" {{ cfgFile }}'

setting_{{ stigId }}-{{ parmName }}:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '{{ parmVal }}'
