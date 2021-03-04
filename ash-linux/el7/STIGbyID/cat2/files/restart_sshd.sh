# Restart sshd service if any of:
# 
# Cause changes to the /etc/ssh/sshd_config file
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "Service Restart: sshd"
diag_out "   Restart the sshd service if any of:"
diag_out "   * file_RHEL-07-040690"
diag_out "   * file_RHEL-07-040680"
diag_out "   * file_RHEL-07-040660"
diag_out "   * file_RHEL-07-040700"
diag_out "   * file_RHEL-07-040670"
diag_out "   Change the /etc/ssh/sshd_config file"
diag_out "----------------------------------------"

