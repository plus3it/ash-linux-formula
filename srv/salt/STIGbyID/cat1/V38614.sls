# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38614
# Finding ID:	V-38614
# Version:	RHEL-06-000239
# Finding Level:	High
#
#     The SSH daemon must not allow authentication using an empty password. 
#     Configuring this setting for the SSH daemon provides additional 
#     assurance that remote login via SSH will require a password, even in 
#     the event of misconfiguration elsewhere.
#
############################################################

script_V38614-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38614.sh

file_V38614:
  file.replace:
  - name: /etc/ssh/sshd_config
  - pattern: "^PermitEmptyPasswords .*"
  - repl: "PermitEmptyPasswords no"
  - onlyif: 'egrep "^PermitEmptyPasswords yes" /etc/ssh/sshd_config'
