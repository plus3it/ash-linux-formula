# STIG URL:
# Finding ID:	RHEL-07-020300
# Version:	RHEL-07-020300_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     All GIDs referenced in the /etc/passwd file must be defined in 
#     the /etc/group file.
#
# CCI-000764
#    NIST SP 800-53 :: IA-2
#    NIST SP 800-53A :: IA-2.1
#    NIST SP 800-53 Revision 4 :: IA-2
#
#################################################################
{%- set stig_id = 'RHEL-07-020300' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for user in salt['user.getent']('') %}
{%- set ID = user['name'] %}
{%- if not salt['file.search']('/etc/group', ':' + user['gid']|string() + ':' ) %}
notify_{{ stig_id }}-{{ ID }}:
  cmd.run:
    - name: 'echo "The {{ ID }} users GID [{{ user['gid'] }}] is not mapped in /etc/group."'
{%- endif %}
{%- endfor %}

# Probably want output indicating that no unmapped GIDs were found...
