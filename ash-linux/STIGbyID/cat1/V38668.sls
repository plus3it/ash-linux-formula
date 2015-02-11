# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38668
# Finding ID:	V-38668 
# Version:	RHEL-06-000286
#
#     A locally logged-in user who presses Ctrl-Alt-Delete, when at the 
#     console, can reboot the system. If accidentally pressed, as could 
#     happen in the case of mixed OS environment, this can create the risk 
#     of short-term loss of availability of systems due to unintentional 
#     reboot. In the GNOME graphical environment, risk of unintentional 
#     reboot from the Ctrl-Alt-Delete sequence is reduced because the user 
#     will be prompted before any action is taken. 
#
###########################################################################

script_V38668-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat1/files/V38668.sh
    - cwd: /root

{% set distCAD = '/etc/init/control-alt-delete.conf' %}
{% set overrideCAD = '/etc/init/control-alt-delete.override' %}

{% if not salt['file.file_exists'](overrideCAD) %}
notify_V38668-override:
  cmd.run:
    - name: 'echo "Creating ''{{ overrideCAD }}''"'

copy_V38668-override:
  file.copy:
    - source: '{{ distCAD }}'
    - cwd: /root
    - name: '{{ overrideCAD }}'

edit_V38668-override:
  file.replace:
    - name: '{{ overrideCAD }}'
    - pattern: '\/sbin.*now'
    - repl: '/bin/logger -p kern.crit '

{% else %}
notify_V38668-override:
  cmd.run:
    - name: 'echo "Nothing to do: {{ overrideCAD }} already exists."'

{% endif %}
# file_V38668_managed:
#   file.managed:
#     - name: /etc/init/control-alt-delete.override
#     - source: salt://ash-linux/STIGbyID/cat1/files/V38668.txt
#     - cwd: /root
#     - force: True
