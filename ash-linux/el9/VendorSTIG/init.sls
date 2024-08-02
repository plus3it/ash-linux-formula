# Due to hardening "misses" in the releases of official STIGs from
# DISA, this code-branch will use to run content released through the
# OSCAP project. Because the OSCAP project's content _can_ "over
# harden" systems, this code-branch will also run content to undo
# any such hardening that is proven to be consistently-problematic.
#
# Further, some supplemental hardening-content - to address gaps that
# do not yet (or will never) have suitable DISA- or OSCAP-provied
# content - will be located in this code-branch
#
######################################################################

include:
  - ash-linux.el9.VendorSTIG.packages
  - ash-linux.el9.VendorSTIG.remediate
  - ash-linux.el9.VendorSTIG.scap_undos
  - ash-linux.el9.VendorSTIG.aws_cli_v2
