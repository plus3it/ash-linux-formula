#!/bin/sh

##########################################
CURRENT_DIR=`/usr/bin/dirname $0`
RPM=/bin/rpm
CURDATE=`date +%Y%m%d-%H%M%S`
INSTLOG=$CURRENT_DIR/install_log.$CURDATE
OSVERSION=`/bin/awk '{print $3}' /etc/centos-release`
VERSION=1.0
##########################################

echo " " 2>&1 | tee -a $INSTLOG
echo "Installing post core packages on `/bin/date`" 2>&1 | tee -a $INSTLOG
echo " " 2>&1 | tee -a $INSTLOG

$RPM -qa | sort > $CURRENT_DIR/pre.txt

$RPM -ivh $CURRENT_DIR/*.rpm 2>&1 | tee -a $INSTLOG

$RPM -qa | sort > $CURRENT_DIR/post.txt

echo " " 2>&1 | tee -a $INSTLOG
echo "Post install routine complete on `/bin/date`" 2>&1 | tee -a $INSTLOG
echo " " 2>&1 | tee -a $INSTLOG

echo "$CURDATE | $OSVERSION | $VERSION | Completed install of primary RPMs for core stage 2 of 2" >> /etc/.icgc-cm.log
