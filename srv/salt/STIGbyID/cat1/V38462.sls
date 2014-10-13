# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38462
# Finding ID:	V-38462
# Version:	RHEL-06-000514
#
#      Ensuring all packages' cryptographic signatures are valid prior
#      to installation ensures the provenance of the software and
#      protects against malicious tampering. 
#
###########################################################################

script_V38462-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38462.sh

cmd-etc_rpmrc:
  cmd.run:
  - name: 'sed -e "/nosignature/s/^/## /" /etc/rpmrc'
  - onlyif: 'test -s /etc/rpmrc && grep nosignature /etc/rpmrc'

cmd_V38462-lib_rpmrc:
  cmd.run:
  - name: 'sed -e "/nosignature/s/^/## /" /usr/lib/rpm/rpmrc'
  - onlyif: 'test -s /usr/lib/rpm/rpmrc && grep nosignature /usr/lib/rpm/rpmrc'

cmd_V38462-redhat_rpmrc:
  cmd.run:
  - name: 'sed -e "/nosignature/s/^/## /" /usr/lib/rpm/redhat/rpmrc'
  - onlyif: 'test -s /usr/lib/rpm/redhat/rpmrc && grep nosignature /usr/lib/rpm/redhat/rpmrc'

file_V38462-root_rpmrc:
  cmd.run:
  - name: 'sed -e "/nosignature/s/^/## /" /root/.rpmrc'
  - onlyif: 'test -s /root/.rpmrc && grep nosignature /root/.rpmrc'
