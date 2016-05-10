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

{%- set stig_id = '38668' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}
{%- set overrideCAD = '/etc/init/control-alt-delete.override' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

file_V{{ stig_id }}_managed:
  file.managed:
    - name: '{{ overrideCAD }}'
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.txt
    - cwd: /root
    - replace: False

edit_V{{ stig_id }}-override:
  file.replace:
    - name: '{{ overrideCAD }}'
    - pattern: '\/sbin.*now '
    - repl: '/bin/logger -p security.info '
    - require:
      - file: file_V{{ stig_id }}_managed
    - onlyif:
      - 'test -f {{ overrideCAD }}'
