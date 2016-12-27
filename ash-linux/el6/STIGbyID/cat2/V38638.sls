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
#  CCI: CCI-000057
#  NIST SP 800-53 :: AC-11 a
#  NIST SP 800-53A :: AC-11.1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-11 a
#
############################################################

{%- set stigId = 'V38638' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.pkg.version('gdm') %}
cmd_{{ stigId }}-autoLock:
  cmd.run:
    - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gnome-screensaver/lock_enabled true'
{%- else %}
notify_{{ stigId }}:
  cmd.run:
    - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{%- endif %}

