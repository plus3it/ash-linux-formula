# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38537
# Rule ID:		sysctl_net_ipv4_icmp_ignore_bogus_error_responses
# Finding ID:		V-38537
# Version:		RHEL-06-000093
# SCAP Security ID:	CCE-26993-6
# Finding Level:	Low
#
#     The system must ignore ICMPv4 bogus error responses. Ignoring bogus
#     ICMP error responses reduces log size, although some activity would
#     not be logged.
#
############################################################

{%- set stig_id = 'V38537' %}
{%- set scapId = 'CCE-26993-6' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.icmp_ignore_bogus_error_responses' %}
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
    - name: 'printf "NOTE: In-memory configuration already disables\n      responding to ICMPv4 broadcast echo\n      requests\n"'
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
