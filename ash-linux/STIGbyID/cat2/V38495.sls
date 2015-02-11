# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38495
# Finding ID:	V-38495
# Version:	RHEL-06-000384
# Finding Level:	Medium
#
#     Audit log files must be owned by root. If non-privileged users can 
#     write to audit logs, audit trails can be modified or destroyed.
#
#  CCI: CCI-000162
#  NIST SP 800-53 :: AU-9
#  NIST SP 800-53A :: AU-9.1
#  NIST SP 800-53 Revision 4 :: AU-9
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
