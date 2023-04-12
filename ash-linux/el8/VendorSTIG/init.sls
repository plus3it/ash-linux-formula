# Due to continued lapses in the release of an official STIG from
# DISA, # this code-branch will use to run the vendor-provided
# STIG profiles by way of the `oscap` suite of tests and
# remediations.
#
#################################################################

include:
  - ash-linux.el8.VendorSTIG.packages
  - ash-linux.el8.VendorSTIG.remediate
  - ash-linux.el8.VendorSTIG.aws_cli_v2
