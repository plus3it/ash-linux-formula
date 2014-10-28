# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38667
# Finding ID:	V-38667
# Version:	RHEL-06-000285
# Finding Level:	Medium
#
#     Adding host-based intrusion detection tools can provide the 
#     capability to automatically take actions in response to malicious 
#     behavior, which can provide additional agility in reacting to network 
#     threats. These tools also often include a reporting capability to 
#     provide network awareness of system, which may not otherwise exist in 
#     an organization's systems management regime. 
#
############################################################################

script_V38667-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38667.sh

# Not functional in current Salt verion (err: "State selinux.mode found is unavailable")
## enforcing:
##   selinux.mode
######################################################################

cmd_V38667-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

