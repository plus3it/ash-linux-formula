# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38677
# Finding ID:	V-38677
# Version:	RHEL-06-000309
# Finding Level:	High
#
#     The NFS server must not have the insecure file locking option 
#     enabled. Allowing insecure file locking could allow for sensitive 
#     data to be viewed or edited by an unauthorized user.
#
############################################################

script_V38677:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38677.sh

cmd_V38677:
  cmd.run:
  - name: 'sed -i -e "s/,insecure_locks//" -e "s/insecure_locks,//" /etc/exports'
  - require:
    - cmd: script_V38677


