# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38639
# Finding ID:	V-38639
# Version:	RHEL-06-000260
# Finding Level:	Low
#
#     The system must display a publicly-viewable pattern during a 
#     graphical desktop environment session lock. Setting the screensaver 
#     mode to blank-only conceals the contents of the display from 
#     passersby.
#
############################################################

script_V38639-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38639.sh

{% if salt['pkg.version']('gdm') %}
cmd_V38639-setNoUserlist:
  cmd.run:
  - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type string --set /apps/gnome-screensaver/mode blank-only'
{% else %}
notify_V38639:
  cmd.run:
  - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken
)"'
{% endif %}
