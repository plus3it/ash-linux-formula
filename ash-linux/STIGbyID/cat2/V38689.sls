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

script_V38689-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38689.sh

{% if salt['pkg.version']('gdm') %}
  {% if salt['file.file_exists']('/etc/issue') %}
cmd_V38689-setBanner:
  cmd.run:
    - name: '/usr/bin/gconftool-2 --direct --config-source=xml:readwrite:$HOME/.gconf --type string --set /apps/gdm/simple-greeter/banner_message_text "$(cat /etc/issue)"'
  {% else %}
cmd_V38689-setBanner:
  cmd.run:
    - name: 'echo "WARNING: Could not find /etc/banner file: GDM login banner not set!"'
  {% endif %}
{% else %}
notify_V38689:
  cmd.run:
    - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{% endif %}
