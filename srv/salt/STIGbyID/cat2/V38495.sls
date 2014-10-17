# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38495
# Finding ID:	V-38495
# Version:	RHEL-06-000384
# Finding Level:	Medium
#
#     Audit log files must be owned by root. If non-privileged users can 
#     write to audit logs, audit trails can be modified or destroyed.
#
############################################################

script_V38495-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38495.sh

directory_V38495:
  file.directory:
  - name: /var/log/audit
  - user: root
  - recurse:
    - user

