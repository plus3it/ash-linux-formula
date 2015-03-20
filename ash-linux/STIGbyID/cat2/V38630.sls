# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38630
# Finding ID:	V-38630
# Version:	RHEL-06-000258
# Finding Level:	Medium
#
#     The graphical desktop environment must automatically lock after 15 
#     minutes of inactivity and the system must require user to 
#     re-authenticate to unlock the environment. Enabling idle activation 
#     of the screen saver ensures the screensaver will be activated after 
#     the idle delay. Applications requiring continuous, real-time screen 
#     display (such as network management ...
#
#  CCI: CCI-000057
#  NIST SP 800-53 :: AC-11 a
#  NIST SP 800-53A :: AC-11.1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-11 a
#
############################################################

script_V38630-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38630.sh
    - cwd: '/root'

{%- if salt['pkg.version']('gdm') %}
cmd_V38630-idleConfig:
  cmd.run:
    - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gnome-screensaver/idle_activation_enabled true'
{%- else %}
notify_V38630:
  cmd.run:
    - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{%- endif %}

