# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38489
# Finding ID:	V-38489
# Version:	RHEL-06-000016
# Finding Level:	Medium
#
#     A file integrity tool must be installed. The AIDE package must be 
#     installed if it is to be available for integrity checking.
#
#  CCI: CCI-000663
#  NIST SP 800-53 :: SA-7
#  NIST SP 800-53A :: SA-7.1 (ii)
#
############################################################

script_V38489-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38489.sh

pkg_V38489:
  pkg.installed:
  - name: aide

