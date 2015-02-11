# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38487
# Finding ID:	V-38487
# Version:	RHEL-06-000015
# Finding Level:	Low
#
#     The system package management tool must cryptographically verify the 
#     authenticity of all software packages during installation. Ensuring 
#     all packages' cryptographic signatures are valid prior to 
#     installation ensures the provenance of the software and protects 
#     against malicious tampering.
#
############################################################

script_V38487-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38487.sh

##############################################################################
# Need to do this with a custom module. Use:
# - pkg.list_repos
# - pkg.get_repo
# - pkg.mod_repo
# from /usr/lib/python2.6/site-packages/salt/modules/yumpkg.py as references
##############################################################################
script_V38487-fixGpgChk:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38487-helper.sh
