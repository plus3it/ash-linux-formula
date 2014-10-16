# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38481
# Finding ID:	V-38481
# Version:	RHEL-06-000011
# Finding Level:	Medium
#
#     System security patches and updates must be installed and up-to-date. 
#     Installing software updates is a fundamental mitigation against the 
#     exploitation of publicly-known vulnerabilities.
#
############################################################

include:
- STIGbyID/cat2/V38481

cmd_38481-remediate:
  cmd.run:
  - name: 'yum update -y'
  - unless: 'yum repolist | grep "repolist: 0"'
