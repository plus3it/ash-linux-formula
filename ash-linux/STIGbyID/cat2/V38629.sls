# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38629
# Finding ID:	V-38629
# Version:	RHEL-06-000257
# Finding Level:	Medium
#
#     The graphical desktop environment must set the idle timeout to no 
#     more than 15 minutes. Setting the idle delay controls when the 
#     screensaver will start, and can be combined with screen locking to 
#     prevent access from passersby.
#
#  CCI: CCI-000057
#  NIST SP 800-53 :: AC-11 a
#  NIST SP 800-53A :: AC-11.1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-11 a
#
############################################################

script_V38629-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38629.sh

{% if salt['pkg.version']('gdm') %}
cmd_V38629-idleConfig:
  cmd.run:
    - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type int --set /apps/gnome-screensaver/idle_delay 15'
{% else %}
notify_V38629:
  cmd.run:
    - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{% endif %}

