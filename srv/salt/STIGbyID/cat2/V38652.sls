# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38652
# Finding ID:	V-38652
# Version:	RHEL-06-000269
# Finding Level:	Medium
#
#     Remote file systems must be mounted with the nodev option. Legitimate 
#     device files should only exist in the /dev directory. NFS mounts 
#     should not present device files to users.
#
############################################################

script_V38652-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38652.sh

cmd_V38652-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

