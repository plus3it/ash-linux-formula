#!/bin/sh

##########################################
CURRENT_DIR=`/usr/bin/dirname $0`
RPM=/bin/rpm
CURDATE=`date +%Y%m%d-%H%M%S`
INSTLOG=$CURRENT_DIR/install_log.$CURDATE
CHKCONFIG=/sbin/chkconfig
OSVERSION=`/bin/awk '{print $3}' /etc/centos-release`
VERSION=1.0
##########################################

echo " " 2>&1 | tee -a $INSTLOG
echo "Installing DIA Desktop packages on `/bin/date`" 2>&1 | tee -a $INSTLOG
echo " " 2>&1 | tee -a $INSTLOG

#*****************************************

# Stop nails if running
/sbin/chkconfig nails > /dev/null 2>&1
if [ $? -eq "0" ]; then
  /sbin/service nails stop 2>&1 | tee -a $INSTLOG
fi

#*****************************************

$RPM -qa | sort > $CURRENT_DIR/pre.txt

$RPM -ivh $CURRENT_DIR/*.rpm 2>&1 | tee -a $INSTLOG

$RPM -qa | sort > $CURRENT_DIR/post.txt

# Perform cleanup

rm -rf $CURRENT_DIR/*.rpm 2>&1 | tee -a $INSTLOG

#*****************************************

$CHKCONFIG NetworkManager off 2>&1 | tee -a $INSTLOG

#*****************************************

# Start nails back up
/sbin/chkconfig nails > /dev/null 2>&1
if [ $? -eq "0" ]; then
  /sbin/service nails start 2>&1 | tee -a $INSTLOG
fi

#*****************************************

echo " " 2>&1 | tee -a $INSTLOG
echo "DIA Desktop install routine complete on `/bin/date`" 2>&1 | tee -a $INSTLOG
echo " " 2>&1 | tee -a $INSTLOG
echo "$CURDATE | $OSVERSION | $VERSION | Completed installation of DIA Desktop RPM stack" >> /etc/.icgc-cm.log
