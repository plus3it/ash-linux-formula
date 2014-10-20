# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38484
# Finding ID:	V-38484
# Version:	RHEL-06-000507
# Finding Level:	Medium
#
#     The operating system, upon successful logon, must display to the user 
#     the date and time of the last logon or access via ssh. Users need to 
#     be aware of activity that occurs regarding their account. Providing 
#     users with information regarding the date and time of their last 
#     successful login allows the user to determine if any ...
#
############################################################

script_V38484-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38484.sh

file_V38484-repl:
  file.replace:
  - name: /etc/ssh/sshd_config
  - pattern: "^PrintLastLog.*$"
  - repl: "PrintLastLog yes"

file_V38484-add:
  file.append:
  - name: /etc/ssh/sshd_config
  - text: 'PrintLastLog yes'
  - onlyif: 'grep ^PrintLastLog /etc/ssh/sshd_config'
