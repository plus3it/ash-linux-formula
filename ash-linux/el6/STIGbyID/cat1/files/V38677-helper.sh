#!/bin/sh
#
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

echo "Before fix:"
sed 's/^/   /' /etc/exports

sed -i '{
   s/,insecure_locks)/)/
   s/(insecure_locks,/(/
   s/,insecure_locks,/,/
   s/(insecure_locks)//
}' /etc/exports

echo "After fix:"
sed 's/^/   /' /etc/exports
