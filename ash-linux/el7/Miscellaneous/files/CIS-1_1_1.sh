# Rule Name:    sshd_set_loglevel_info
# CIS Rule ID:  1.1.1
#
# Rule Summary:
#	Disable non-standard or non-native filesystem-types:
#
#   A number of uncommon filesystem types are supported under
#   Linux. Removing support for unneeded filesystem types
#   reduces the local attack surface of the system. If a
#   filesystem type is not needed it should be disabled. Native
#   Linux file systems are designed to ensure that built-in
#   security controls function as expected. Non-native
#   filesystems can lead to unexpected consequences to both the
#   security and functionality of the system and should be used
#   with caution. Many filesystems are created for niche use
#   cases and are not maintained and supported as the operating
#   systems are updated and patched. Users of non-native
#   filesystems should ensure that there is attention and
#   ongoing support for them, especially in light of frequent
#   operating system changes.
#
#   Standard network connectivity and Internet access to cloud
#   storage may make the use of non-standard filesystem formats
#   to directly attach heterogeneous devices much less
#   attractive
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "CIS Benchmark ID: 1.1.1"
diag_out "   Disable non-standard or non-native"
diag_out "   filesystem-types"
diag_out "----------------------------------------"

