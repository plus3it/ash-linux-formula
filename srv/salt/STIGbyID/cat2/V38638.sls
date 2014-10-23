# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38638
# Finding ID:	V-38638
# Version:	RHEL-06-000259
# Finding Level:	Medium
#
#     The graphical desktop environment must have automatic lock enabled. 
#     Enabling the activation of the screen lock after an idle period 
#     ensures password entry will be required in order to access the 
#     system, preventing access by passersby.
#
############################################################

script_V38638.g-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38638.g.sh

{% if salt['pkg.version']('gdm') %}
cmd_V38638-autoLock:
  cmd.run:
  - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gnome-screensaver/lock_enabled true 
{% else %}
notify_V38638:
  cmd.run:
  - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{% endif %}

