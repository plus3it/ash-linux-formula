# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38491
# Finding ID:	V-38491
# Version:	RHEL-06-000019
# Finding Level:	High
#
#     There must be no .rhosts or hosts.equiv files on the system. Trust
#     files are convenient, but when used in conjunction with the
#     R-services, they can allow unauthenticated access to a system.
#
############################################################

{%- set stigId = 'V38491' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}
{%- set hostsEquiv = '/etc/hosts.equiv' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.file.file_exists(hostsEquiv) %}
file_{{ stigId }}-hostsEquiv:
  file.absent:
    - name: {{ hostsEquiv }}
{%- else %}
file_{{ stigId }}-hostsEquiv:
  cmd.run:
    - name: 'echo "No ''{{ hostsEquiv }}'' file found"'
{%- endif %}

# Iterate locally-managed users to look for .rhosts files
{%- for userName in salt['ash.shadow_list_users']() %}
{%- set userInfo = salt['user.info'](userName) %}
{%- set userHome = userInfo['home'] %}
{%- set userRhost = userHome + '/.rhosts' %}
{%- if salt.file.file_exists(userRhost) %}
notify-{{ userName }}:
  cmd.run:
    - name: 'echo "WARNING: User ''{{ userName }}'' has an ''.rhosts'' file. Removing..."'
cmd_{{ stigId }}-{{ userRhost }}_remove:
  file.absent:
    - name: '{{ userRhost }}'
{%- else %}
notify-{{ userName }}:
  cmd.run:
    - name: 'echo "Info: User ''{{ userName }}'' does not have an ''.rhosts'' file."'
{%- endif %}
{%- endfor %}
