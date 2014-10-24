# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38654
# Finding ID:	V-38654
# Version:	RHEL-06-000270
# Finding Level:	Medium
#
#     Remote file systems must be mounted with the nosuid option. NFS 
#     mounts should not present suid binaries to users. Only 
#     vendor-supplied suid executables should be installed to their default 
#     location on the local filesystem.
#
############################################################

script_V38654-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38654.sh

cmd_V38654-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

