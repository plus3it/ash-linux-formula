# Due to continued lapses in the release of an official STIG from
# DISA, # this code-branch will use to run the vendor-provided
# STIG profiles by way of the `oscap` suite of tests and
# remediations.
#
#################################################################

include:
  - ash-linux.el7.STIGbyID.cat2.RHEL-07-020260
  - ash-linux.el7.VendorSTIG.packages
  - ash-linux.el7.VendorSTIG.remediate
  - ash-linux.el7.VendorSTIG.cat2
  - ash-linux.el7.VendorSTIG.cat3
  - ash-linux.el7.STIGbyID.cat2.RHEL-07-010040
  - ash-linux.el7.STIGbyID.cat2.RHEL-07-040110
  - ash-linux.el7.STIGbyID.cat2.RHEL-07-040170
  - ash-linux.el7.STIGbyID.cat2.RHEL-07-040400
  - ash-linux.el7.Miscellaneous.firewalld_safeties
  - ash-linux.el7.Miscellaneous.CIS-5_2_3
  - ash-linux.el7.Miscellaneous.CIS-5_2_5
  - ash-linux.audit_load
