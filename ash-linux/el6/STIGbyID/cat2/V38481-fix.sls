# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38481
# Finding ID:	V-38481
# Version:	RHEL-06-000011
# Finding Level:	Medium
#
#     System security patches and updates must be installed and up-to-date. 
#     Installing software updates is a fundamental mitigation against the 
#     exploitation of publicly-known vulnerabilities.
#
#  CCI: CCI-001233
#  NIST SP 800-53 :: SI-2 (2)
#  NIST SP 800-53A :: SI-2 (2).1 (ii)
#  NIST SP 800-53 Revision 4 :: SI-2 (2)
#
############################################################

include:
  - ash-linux.el6.STIGbyID.cat2.V38481

remediate_V38481-updateRPMs:
  pkg.uptodate
