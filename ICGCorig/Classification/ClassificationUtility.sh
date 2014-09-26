#!/bin/sh

# This script will setup the default background appropriate for
# the classification of this system
# Options: TS-SCI, SECRET, UNCLASS, STONEGHOST

#***********************************************************

if [ "$1x" = "x" ]; then
        class=UNCLASS
else
        class=$1
fi

#***********************************************************

CURRENT_DIR=`/usr/bin/dirname $0`
CURDATE=`date +%Y%m%d-%H%M%S`
INSTLOG=$CURRENT_DIR/install_log.$CURDATE
BACKGROUND_DEST=/usr/share/backgrounds/images/default.jpg
BG_XML_DIR=/usr/share/backgrounds
OSVERSION=`/bin/awk '{print $3}' /etc/centos-release`
VERSION=1.0

#***********************************************************

# Back up /etc/inittab then change runlevel from 3 to 5

#cp -p /etc/inittab /etc/.inittab.$CURDATE 2>&1 | tee -a $INSTLOG

#cat /etc/inittab | sed -e 's/id:3:initdefault:/id:5:initdefault:/g' > /tmp/1

#mv -f /tmp/1 /etc/inittab 2>&1 | tee -a $INSTLOG

#chmod 400 /etc/inittab 2>&1 | tee -a $INSTLOG
#chown root:root /etc/inittab 2>&1 | tee -a $INSTLOG

#***********************************************************

cp -p $BG_XML_DIR/default.xml $BG_XML_DIR/.default.xml.$CURDATE 2>&1 | tee -a $INSTLOG

if [ ! -d $BG_XML_DIR/images ]; then
  mkdir $BG_XML_DIR/images 2>&1 | tee -a $INSTLOG
  chmod 755 $BG_XML_DIR/images 2>&1 | tee -a $INSTLOG
  chown root:root $BG_XML_DIR/images 2>&1 | tee -a $INSTLOG
fi

# Replace lines in default.xml
cat $BG_XML_DIR/default.xml | sed -e 's/\/usr\/share\/backgrounds\/default_1920x1200.png/\/usr\/share\/backgrounds\/images\/default.jpg/g' \
> $BG_XML_DIR/default.xml.new

mv -f $BG_XML_DIR/default.xml.new $BG_XML_DIR/default.xml

cat $BG_XML_DIR/default.xml | sed -e 's/\/usr\/share\/backgrounds\/default_1920x1440.png/\/usr\/share\/backgrounds\/images\/default.jpg/g' \
> $BG_XML_DIR/default.xml.new

mv -f $BG_XML_DIR/default.xml.new $BG_XML_DIR/default.xml

chmod 644 $BG_XML_DIR/default.xml 2>&1 | tee -a $INSTLOG
chown root:root $BG_XML_DIR/default.xml 2>&1 | tee -a $INSTLOG

# Copy image file

if [ "$class" = "TS-SCI" ]; then
 cp -f $CURRENT_DIR/DoDIISsci.jpg $BACKGROUND_DEST 2>&1 | tee -a $INSTLOG
 chmod 644 $BACKGROUND_DEST 2>&1 | tee -a $INSTLOG
 echo "Setting default background classification to TS-SCI" 2>&1 | tee -a $INSTLOG
 echo "$CURDATE | $OSVERSION | $VERSION | Completed setting of background classification to TS-SCI" >> /etc/.icgc-cm.log

elif [ "$class" = "SECRET" ]; then
 cp -f $CURRENT_DIR/DoDIISsec.jpg $BACKGROUND_DEST 2>&1 | tee -a $INSTLOG
 chmod 644 $BACKGROUND_DEST 2>&1 | tee -a $INSTLOG
 echo "Setting default background classification to SECRET" 2>&1 | tee -a $INSTLOG
 echo "$CURDATE | $OSVERSION | $VERSION | Completed setting of background classification to SECRET" >> /etc/.icgc-cm.log

elif [ "$class" = "UNCLASS" ]; then
 cp -f $CURRENT_DIR/DoDIISunc.jpg $BACKGROUND_DEST 2>&1 | tee -a $INSTLOG
 chmod 644 $BACKGROUND_DEST 2>&1 | tee -a $INSTLOG
 echo "Setting default background classification to UNCLASS" 2>&1 | tee -a $INSTLOG
 echo "$CURDATE | $OSVERSION | $VERSION | Completed setting of background classification to UNCLASS" >> /etc/.icgc-cm.log

elif [ "$class" = "STONEGHOST" ]; then
 cp -f $CURRENT_DIR/DoDIISstone.jpg $BACKGROUND_DEST 2>&1 | tee -a $INSTLOG
 chmod 644 $BACKGROUND_DEST 2>&1 | tee -a $INSTLOG
 echo "Setting default background classification to STONEGHOST" 2>&1 | tee -a $INSTLOG
 echo "$CURDATE | $OSVERSION | $VERSION | Completed setting of background classification to STONEGHOST" >> /etc/.icgc-cm.log

else
 echo "Select one of the following values: TS-SCI, SECRET, UNCLASS, STONEGHOST" 2>&1 | tee -a $INSTLOG
fi

# End Script
