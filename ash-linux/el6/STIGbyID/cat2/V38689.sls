# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38689
# Finding ID:	V-38689
# Version:	RHEL-06-000326
# Finding Level:	Medium
#
#     A login banner must be displayed immediately prior to, or as part of, 
#     graphical desktop environment login prompts. An appropriate warning 
#     message reinforces policy awareness during the logon process and 
#     facilitates possible legal action against attackers.
#
#  CCI: 
#       CCI-001384
#       CCI-001385
#       CCI-001386
#       CCI-001387
#       CCI-001388
#  NIST SP 800-53 :: AC-8 c
#  NIST SP 800-53A :: AC-8.2 (i)
#  NIST SP 800-53 Revision 4 ::
#       AC-8 c 1
#       AC-8.2 (ii),AC-8 c 2
#       AC-8.2 (ii),AC-8 c 2
#       AC-8.2 (ii),AC-8 c 2
#       AC-8.2 (iii),AC-8 c 3
#
############################################################

{%- set stigId = 'V38689' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.pkg.version('gdm') %}
  {%- if salt.file.file_exists('/etc/issue') %}
cmd_{{ stigId }}-setBanner:
  cmd.run:
    - name: '/usr/bin/gconftool-2 --direct --config-source=xml:readwrite:$HOME/.gconf --type string --set /apps/gdm/simple-greeter/banner_message_text "$(cat /etc/issue)"'
  {%- else %}
cmd_{{ stigId }}-setBanner:
  cmd.run:
    - name: 'echo "WARNING: Could not find /etc/banner file: GDM login banner not set!"'
  {%- endif %}
{%- else %}
notify_{{ stigId }}:
  cmd.run:
    - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{%- endif %}
