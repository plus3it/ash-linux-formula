# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38688
# Finding ID:	V-38688
# Version:	RHEL-06-000324
# Finding Level:	Medium
#
#     A login banner must be displayed immediately prior to, or as part of, 
#     graphical desktop environment login prompts. An appropriate warning 
#     message reinforces policy awareness during the logon process and 
#     facilitates possible legal action against attackers.
#
#  CCI: CCI-000050
#  NIST SP 800-53 :: AC-8 b
#  NIST SP 800-53A :: AC-8.1 (iii)
#  NIST SP 800-53 Revision 4 :: AC-8 b
#
############################################################

{%- set stigId = 'V38688' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

# Make sure GDM is installed and enable GDM login banners
{%- if salt.pkg.version('gdm') %}
cmd_{{ stigId }}-enableBanner:
  cmd.run:
    - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gdm/simple-greeter/banner_message_enable true'
{%- else %}
notify_{{ stigId }}:
  cmd.run:
    - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{%- endif %}
