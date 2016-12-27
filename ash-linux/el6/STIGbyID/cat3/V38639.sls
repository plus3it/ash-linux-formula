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

{%- set stigId = 'V38639' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('gdm') %}
cmd_{{ stigId }}-setNoUserlist:
  cmd.run:
    - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type string --set /apps/gnome-screensaver/mode blank-only'
{%- else %}
notify_{{ stigId }}:
  cmd.run:
    - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{%- endif %}
