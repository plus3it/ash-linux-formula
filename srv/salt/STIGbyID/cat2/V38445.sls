# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38445
# Finding ID:	V-38445
# Version:	RHEL-06-000522
# Finding Level:	Medium
#
#     Audit log files must be group-owned by root. If non-privileged users 
#     can write to audit logs, audit trails can be modified or destroyed.
#
############################################################

script_V38445-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38445.sh

file_V38445:
  file.directory:
  - name: /var/log/audit
  - group: root
  - recurse:
    - group
