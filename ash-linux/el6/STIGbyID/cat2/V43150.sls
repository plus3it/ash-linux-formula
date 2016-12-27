# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-43150
# Finding ID:	V-43150
# Version:	RHEL-06-000527
# Finding Level:	Medium
#
#     The login user list must be disabled. Leaving the user list enabled 
#     is a security risk since it allows anyone with physical access to the 
#     system to quickly enumerate known user accounts without logging in.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V43150' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.pkg.version('gdm') %}
cmd_{{ stigId }}-setNoUserlist:
  cmd.run:
    - name: '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gdm/simple-greeter/disable_user_list true'
{%- else %}
notify_{{ stigId }}:
  cmd.run:
    - name: 'echo "NOTICE: Graphical desktop system not installed (no action taken)"'
{%- endif %}
