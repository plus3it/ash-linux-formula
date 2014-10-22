# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38595
# Finding ID:	V-38595
# Version:	RHEL-06-000349
# Finding Level:	Medium
#
#     The system must be configured to require the use of a CAC, PIV 
#     compliant hardware token, or Alternate Logon Token (ALT) for 
#     authentication. Smart card login provides two-factor authentication 
#     stronger than that provided by a username/password combination. Smart 
#     cards leverage a PKI (public key infrastructure) in order to provide 
#     and ...
#
############################################################
script_V38595-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38595.sh

cmd_V38595-notice:
  cmd.run:
  - name: 'echo "Not a technical/enforcible control"'
