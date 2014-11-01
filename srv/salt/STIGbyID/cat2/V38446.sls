# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38446
# Finding ID:	V-38446
# Version:	RHEL-06-000521
# Finding Level:	Medium
#
#     The mail system must forward all mail for root to one or more system 
#     administrators. A number of system services utilize email messages 
#     sent to the root user to notify system administrators of active or 
#     impending issues. These messages must be forwarded to at least one 
#     monitored ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38446-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38446.sh

cmd_V38446:
  cmd.run:
  - name: 'echo "Not a technically-implementable control"'
