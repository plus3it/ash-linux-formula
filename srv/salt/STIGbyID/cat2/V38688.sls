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
############################################################

script_V38688-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38688.sh

# Make sure GDM is installed and enable GDM login banners
{% if salt['pkg.version']('gdm') %}
cmd_V38688-enableBanner:
  cmd.run:
  - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gdm/simple-greeter/banner_message_enable true'

# Make sure the /etc/issue file contents exist and set GDM banner
  {% if salt['file.file_exists']('/etc/issue') %}
cmd_V38688-setBanner:
  cmd.run:
  - name: '/usr/bin/gconftool-2 --direct --config-source=xml:readwrite:$HOME/.gconf --type string --set /apps/gdm/simple-greeter/banner_message_text "$(cat /etc/issue)"'
  {% else %}

cmd_V38688-setBanner:
  cmd.run:
  - name: 'echo "WARNING: Could not find /etc/banner file: GDM login banner not set!"'
  {% endif %}
{% else %}
notify_V38688:
  cmd.run:
  - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{% endif %}

