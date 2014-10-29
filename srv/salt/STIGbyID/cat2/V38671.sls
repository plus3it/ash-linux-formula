# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38671
# Finding ID:	V-38671
# Version:	RHEL-06-000288
# Finding Level:	Medium
#
#     The sendmail package must be removed. The sendmail software was not 
#     developed with security in mind and its design prevents it from being 
#     effectively contained by SELinux. Postfix should be used instead.
#
############################################################

script_V38671-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38671.sh

pkg_V38671-remove:
  pkg.purged:
  - name: 'sendmail'
