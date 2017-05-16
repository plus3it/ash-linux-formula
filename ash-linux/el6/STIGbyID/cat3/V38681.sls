# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38681
# Finding ID:	V-38681
# Version:	RHEL-06-000294
# Finding Level:	Low
#
#     All GIDs referenced in /etc/passwd must be defined in /etc/group
#     Inconsistency in GIDs between /etc/passwd and /etc/group could lead
#     to a user having unintended rights.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38681' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- for user in salt.ash.shadow_list_users() %}
{%- set userinfo = salt.user.info(user) %}
{%- if not salt.file.search('/etc/group', ':' + userinfo.gid|string() + ':' ) %}
notify_{{ stigId }}-{{ ID }}:
  cmd.run:
    - name: 'echo "The {{ user }} users GID [{{ userinfo['gid'] }}] is not mapped in /etc/group."'
{%- endif %}
{%- endfor %}

# Probably want output indicating that no unmapped GIDs were found...
