#!/bin/sh

##########################################
PATH=$PATH:/sbin:/usr/sbin:/bin:/sbin
export PATH
CURRENT_DIR=`/usr/bin/dirname $0`
CURDATE=`date +%Y%m%d-%H%M%S`
INSTLOG=$CURRENT_DIR/package_removal_log.$CURDATE
RPM=/bin/rpm
VERSION=1.0
OSVERSION=`/bin/awk '{print $3}' /etc/centos-release`
##########################################

echo " " 2>&1 | tee -a $INSTLOG
echo "Starting uninstall of primary RPMs to create core on `/bin/date`" 2>&1 | tee -a $INSTLOG
echo " " 2>&1 | tee -a $INSTLOG

$RPM -qa | sort > $CURRENT_DIR/pre.txt

for i in `cat $CURRENT_DIR/to_be_removed.lst`; do
$RPM -q $i > /dev/null 2>&1
  if [ $? != "0" ]; then
    echo "--Package $i not found" 2>&1 | tee -a $INSTLOG
  else
    echo "--Removing: $i" 2>&1 | tee -a $INSTLOG
    /usr/bin/yum -y erase $i 2>&1 | tee -a $INSTLOG
  fi
done

$RPM -qa | sort > $CURRENT_DIR/post.txt

echo " " 2>&1 | tee -a $INSTLOG
echo "Uninstall of primary RPMs complete on `/bin/date`" 2>&1 | tee -a $INSTLOG
echo " " 2>&1 | tee -a $INSTLOG

echo "$CURDATE | $OSVERSION | $VERSION | Completed uninstall of primary RPMs for core stage 1 of 2" >> /etc/.icgc-cm.log
