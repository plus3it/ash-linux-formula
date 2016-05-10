# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - sysctl_net_ipv6_conf_default_accept_ra
#
# Security identifiers:
# - CCE-27164-3
#
# Rule Summary: Disable Accepting IPv6 Router Advertisements
#
# Rule Text: An illicit router advertisement message could result in a 
#            man-in-the-middle attack. This rule should be present in
#            case of intentional or accidental activation of IPv6
#            networking components.
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-27164-3' %}
{%- set parmName = 'net.ipv6.conf.default.accept_ra' %}
{%- set parmVal = '0' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set notify_change = 'In-memory configuration of ''{{ parmName }}'' not disabled' %}
{%- set notify_nochange = '''{{ parmName }}'' already disabled' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

{%- if salt['sysctl.get'](parmName) == parmVal %}
notify_{{ scapId }}-state:
  cmd.run:
    - name: 'echo "{{ notify_nochange }}"'
{%- else %}
notify_{{ scapId }}-state:
  cmd.run:
    - name: 'echo "{{ notify_change }}"'
{%- endif %}

comment_{{ scapId }}-{{ parmName }}:
  file.append:
    - name: '{{ checkFile }}'
    - text: '# Added {{ parmName }} define per SCAP-ID: {{ scapId }}'
    - unless: 'grep "{{ parmName }}[    ]=[     ]{{ parmVal }}" {{ checkFile }}'

setting_{{ scapId }}-{{ parmName }}:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '{{ parmVal }}'
    - onlyif:
      - test -f '/proc/net/if_inet6'
