# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38474
# Finding ID:	V-38474
# Version:	RHEL-06-000508
# Finding Level:	Low
#
#     The system must allow locking of graphical desktop sessions. The 
#     ability to lock graphical desktop sessions manually allows users to 
#     easily secure their accounts should they need to depart from their 
#     workstations temporarily.
#
#  CCI: CCI-000058
#  NIST SP 800-53 :: AC-11 a
#  NIST SP 800-53A :: AC-11
#  NIST SP 800-53 Revision 4 :: AC-11 a
#
############################################################

{%- set stigId = 'V38474' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('gdm') %}
cmd_{{ stigId }}-setNoUserlist:
  cmd.run:
    - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type string --set /apps/gnome_settings_daemon/keybindings/screensaver "l"'
{%- else %}
notify_{{ stigId }}:
  cmd.run:
    - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken
)"'
{%- endif %}
