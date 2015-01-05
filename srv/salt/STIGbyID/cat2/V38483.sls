# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38483
# Finding ID:	V-38483
# Version:	RHEL-06-000013
# Finding Level:	Medium
#
#     The system package management tool must cryptographically verify the 
#     authenticity of system software packages during installation. 
#     Ensuring the validity of packages' cryptographic signatures prior to 
#     installation ensures the provenance of the software and protects 
#     against malicious tampering.
#
#  CCI: CCI-000663
#  NIST SP 800-53 :: SA-7
#  NIST SP 800-53A :: SA-7.1 (ii)
#
############################################################

script_V38483-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38483.sh

file_V38483:
  file.replace:
  - name: /etc/yum.conf
  - pattern: "^gpgcheck=.*$"
  - repl: "gpgcheck=1"

