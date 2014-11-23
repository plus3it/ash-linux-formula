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
  - source: salt://STIGbyID/cat1/files/V38668.sh

file_V38668_managed:
  file.managed:
  - name: /etc/init/control-alt-delete.override
  - source: salt://STIGbyID/cat1/files/V38668.txt
  - force: True
