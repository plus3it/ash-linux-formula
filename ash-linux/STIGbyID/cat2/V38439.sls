# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38439
# Finding ID:	V-38439
# Version:	RHEL-06-000524
# Finding Level:	Medium
#
#     A comprehensive account management process that includes automation 
#     helps to ensure the accounts designated as requiring attention are 
#     consistently and promptly addressed. Enterprise environments make 
#     user account management challenging and complex. A user management 
#     process requiring administrators to manually address account 
#     management functions adds risk of potential oversight. 
#
#  CCI: CCI-000015
#  NIST SP 800-53 :: AC-2 (1)
#  NIST SP 800-53A :: AC-2 (1).1
#  NIST SP 800-53 Revision 4 :: AC-2 (1)
#
############################################################

script_V38439-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38439.sh

cmd_V38439:
  cmd.run:
    - name: 'echo "Not a technically-implementable control"'
