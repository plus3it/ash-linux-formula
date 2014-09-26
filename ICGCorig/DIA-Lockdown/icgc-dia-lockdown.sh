#!/bin/sh
#******************************************
#
#  Date Created: 17 May 2013
#  CHANGELOG:
#        IC GovCloud (ICGC for short)
#	Version = ICGC 1.0, CentOS 6.4 64bit
#
# STIG: RHEL6 STIG, DRAFT, V1, Release 0.3, 05 Feb 2013
# Usage: This script is designed to apply STIG and miscellaneous
#            best practice security settings to a CentOS 6.x OS.
#            Because there is currently no CentOS 6.x STIG, the DISA
#            RHEL6 STIG was used and tested for compatibility, and the
#            equivalent settings have been rolled into the below script.
#            In addition to the RHEL6 STIG, other basic security lockdowns
#            have been included to minimize risk.
#
#            This security script is intended to be applied as a secondary
#            lockdown to the SIMP lockdown. It will layer on additional 
#            security hardening, as well as mandatory consent banners. 
#
#******************************************
PATH=$PATH:/sbin:/usr/sbin:/bin:/sbin
export PATH
CURRENT_DIR=`/usr/bin/dirname $0`
CURDATE=`date +%Y%m%d-%H%M%S`
INSTLOG=$CURRENT_DIR/install_log.$CURDATE
AUDIT_DIR=/etc/audit
NETWORK_DIR=/etc/sysconfig/network-scripts
NETWORK_BKUP_DIR=$CURRENT_DIR/network-scripts_backup
RPM=/bin/rpm
IPTABLES=/sbin/iptables
SERVICE=/sbin/service
CHKCONFIG=/sbin/chkconfig
USERADD=/usr/sbin/useradd
ADMUSER=sysmaint
SUPER=root
CHAGE=/usr/bin/chage
OSVERSION=`/bin/awk '{print $3}' /etc/centos-release`
VERSION=1.0
#******************************************

echo " " 2>&1 | tee -a $INSTLOG
echo "Configuring ICGC system security on `/bin/date`" 2>&1 | tee -a $INSTLOG
echo " " 2>&1 | tee -a $INSTLOG

#******************************************
# Turn off McAfee Nails if present
# Will be turned back on at end

# Stop nails if running
/sbin/chkconfig nails > /dev/null 2>&1
if [ $? -eq "0" ]; then
  /sbin/service nails stop 2>&1 | tee -a $INSTLOG
fi

#******************************************
# SRG-OS-000045 RHEL-06-000005_rule CAT II
# SRG-OS-000047 RHEL-06-000162_rule CAT II
# SRG-OS-000213 RHEL-06-000163_rule CAT II
# SRG-OS-000048 RHEL-06-000311_rule CAT II

echo "-- START: Configuring options in auditd.conf and turning on auditd" 2>&1 | tee -a $INSTLOG

cp -p $AUDIT_DIR/auditd.conf $AUDIT_DIR/.auditd.conf.$CURDATE 2>&1 | tee -a $INSTLOG

##SIMP##sed -e 's/space_left_action =.*/space_left_action = EMAIL/g' $AUDIT_DIR/auditd.conf > $AUDIT_DIR/auditd.conf.TMP
##SIMP##mv -f $AUDIT_DIR/auditd.conf.TMP $AUDIT_DIR/auditd.conf 2>&1 | tee -a $INSTLOG

##SIMP##sed -e 's/admin_space_left_action =.*/admin_space_left_action = email/g' $AUDIT_DIR/auditd.conf > $AUDIT_DIR/auditd.conf.TMP
##SIMP##mv -f $AUDIT_DIR/auditd.conf.TMP $AUDIT_DIR/auditd.conf 2>&1 | tee -a $INSTLOG

# The remainder of these changes are from DLB 2.x:

##SIMP##sed -e 's/flush =.*/flush = SYNC/g' $AUDIT_DIR/auditd.conf > $AUDIT_DIR/auditd.conf.TMP
##SIMP##mv -f $AUDIT_DIR/auditd.conf.TMP $AUDIT_DIR/auditd.conf 2>&1 | tee -a $INSTLOG

sed -e 's/max_log_file_action =.*/max_log_file_action = KEEP_LOGS/g' $AUDIT_DIR/auditd.conf > $AUDIT_DIR/auditd.conf.TMP
mv -f $AUDIT_DIR/auditd.conf.TMP $AUDIT_DIR/auditd.conf 2>&1 | tee -a $INSTLOG

##SIMP##sed -e 's/disk_full_action =.*/disk_full_action = HALT/g' $AUDIT_DIR/auditd.conf > $AUDIT_DIR/auditd.conf.TMP
##SIMP##mv -f $AUDIT_DIR/auditd.conf.TMP $AUDIT_DIR/auditd.conf 2>&1 | tee -a $INSTLOG

##SIMP##sed -e 's/disk_error_action =.*/disk_error_action = HALT/g' $AUDIT_DIR/auditd.conf > $AUDIT_DIR/auditd.conf.TMP
##SIMP##mv -f $AUDIT_DIR/auditd.conf.TMP $AUDIT_DIR/auditd.conf 2>&1 | tee -a $INSTLOG

# This is not a STIG, but increasing the max_log_file size ensures sizes are
# adequate for rotation. This size sets it from 6MB (default) to 16MB based on
# lightweight benchmark testing

sed -e 's/max_log_file =.*/max_log_file = 16/g' $AUDIT_DIR/auditd.conf > $AUDIT_DIR/auditd.conf.TMP
mv -f $AUDIT_DIR/auditd.conf.TMP $AUDIT_DIR/auditd.conf 2>&1 | tee -a $INSTLOG

chmod 400 $AUDIT_DIR/auditd.conf 2>&1 | tee -a $INSTLOG
chown root:root $AUDIT_DIR/auditd.conf 2>&1 | tee -a $INSTLOG

chmod 700 /var/log/audit 2>&1 | tee -a $INSTLOG

$SERVICE auditd restart 2>&1 | tee -a $INSTLOG
$CHKCONFIG --level 12345 auditd on 2>&1 | tee -a $INSTLOG

echo "-- END: Configuring options in auditd.conf and turning on auditd" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000090 RHEL-06-000008_rule
# CAT I

echo "-- START: Installing RPM-GPG-KEY-CentOS-6" 2>&1 | tee -a $INSTLOG

$RPM --import $CURRENT_DIR/RPM_FILES/RPM-GPG-KEY-CentOS-6 2>&1 | tee -a $INSTLOG

echo "-- END: Installing RPM-GPG-KEY-CentOS-6" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Disable last logon on console
# Note: This step needs to be executed early in the lockdown process

##SIMP##echo "-- START: Disabling last logon display on console" 2>&1 | tee -a $INSTLOG

##SIMP##if [ ! -d /etc/gconf/gconf.xml.mandatory ]; then
##SIMP##  echo " " 2>&1 | tee -a $INSTLOG
##SIMP##  echo "  WARNING...could not find /etc/gconf/gconf.xml.mandatory!" \
##SIMP##  2>&1 | tee -a $INSTLOG
##SIMP##  echo " " 2>&1 | tee -a $INSTLOG
##SIMP##fi

##SIMP##/usr/bin/gconftool-2 --config-source xml:readwrite:/etc/gconf/gconf.xml.defaults --direct --type bool --set /apps/gdm/simple-greeter/disable_user_list true

##SIMP##echo "-- END: Disabling last logon display on console" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Set screen saver to 15 minute timeout

##SIMP##echo "-- START: Set screen saver to 15 minute timeout" 2>&1 | tee -a $INSTLOG

##SIMP##/usr/bin/gconftool-2 --direct \
##SIMP##    --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
##SIMP##    --type int \
##SIMP##    --set /apps/gnome-screensaver/idle_delay 15

##SIMP##echo "-- END: Set screen saver to 15 minute timeout" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-999999 RHEL-06-000286_rule CAT I
# Note: traditional modification of /etc/init/control-alt-delete.conf did not
# have an effect on disabling the key sequence in GDM
# The below command disables the GDM power sequence

##SIMP##echo "-- START: Disabling CTL-ALT-DEL using gconftool-2" 2>&1 | tee -a $INSTLOG

##SIMP##/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.defaults --type string --set /apps/gnome_settings_daemon/keybindings/power 'none'

# REF ONLY: This command will reveal the key-value pairs
# /usr/bin/gconftool-2 --get /apps/gnome_settings_daemon/keybindings/power

##SIMP##echo "-- END: Disabling CTL-ALT-DEL using gconftool-2" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000248 RHEL-06-000019_rule
# CAT I

echo "-- START: Removing specific files and locking down home dirs" 2>&1 | tee -a $INSTLOG

for part in `awk '($3 == "ext2" || $3 == "ext3" || $3 == "ext4") { print $2 }' /etc/fstab`
do
  find $part -name .rhosts -exec rm -f {} \;
  find $part -name .shosts -exec rm -f {} \;
  find $part -name hosts.equiv -exec rm -f {} \;
done

# This is not a STIG finding but best practice for new systems
find /home -name '.*' -type f -exec chmod go-rwx {} \;
find /root -name '.*' -type f -exec chmod go-rwx {} \;

echo "-- END: Removing specific files and locking down home dirs" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000109 RHEL-06-000027_rule CAT II
# SRG-OS-000109 RHEL-06-000028_rule CAT III

echo "-- START: Disabling root logins" 2>&1 | tee -a $INSTLOG

cp /etc/securetty /etc/.securetty.$CURDATE 2>&1 | tee -a $INSTLOG

# Note: clearing out /etc/securetty is supposed to restrict root from logging
# into console, however this did not work during testing. To properly prevent
# root logins to the GUI console, a line was added to the gdm-password pam.d
# module (see that section for details)

echo "" > /etc/securetty

# Also part of disabling root logins is to disable root from
# entering via GDM if custom.conf exists

if [ -f /etc/gdm/custom.conf ]; then
  cp -p /etc/gdm/custom.conf /etc/gdm/.custom.conf.$CURDATE 2>&1 | tee -a $INSTLOG
sed -e 's/\[security\]/\[security\]\nAllowRoot=false\n/g' /etc/gdm/custom.conf \
> /etc/gdm/custom.conf.TMP
  mv -f /etc/gdm/custom.conf.TMP /etc/gdm/custom.conf 2>&1 | tee -a $INSTLOG

  chmod 400 /etc/gdm/custom.conf 2>&1 | tee -a $INSTLOG
  chown root:root /etc/gdm/custom.conf 2>&1 | tee -a $INSTLOG
else
  echo " --INFO: /etc/gdm/custom.conf not present" 2>&1 | tee -a $INSTLOG
fi

echo "-- END: Disabling root logins" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000259 RHEL-06-000045_rule 
# CAT II

echo "-- START: Listing all shared libraries that are group-writable or world-writable \
and placing them in $CURRENT_DIR/REVIEW-shlib-files.txt" 2>&1 | tee -a $INSTLOG

for dir in /lib /lib64 /usr/lib /usr/lib64;
do
   find $dir -perm /022 >> $CURRENT_DIR/REVIEW-shlib-files.txt
done

echo "-- END: List of group and world writable files complete" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000259 RHEL-06-000047_rule
# CAT II

echo " -- Listing all executables that are group-writable or world-writable \
and placing them in $CURRENT_DIR/REVIEW-executables-grp-world-writable.txt" \
2>&1 | tee -a $INSTLOG

for dir in /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/bin; 
do
  find $dir -perm /022 >> $CURRENT_DIR/REVIEW-executables-grp-world-writable.txt
done

echo "-- END: List of executables that are g-w writable complete" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000078 RHEL-06-000050_rule CAT II (14 chars)
# SRG-OS-000075 RHEL-06-000051_rule CAT II (cannot change more than once a day)
# SRG-OS-000076 RHEL-06-000053_rule CAT II (60 day expiration)
# SRG-OS-999999 RHEL-06-000054_rule CAT II (warn at 14 days)

echo "-- START: Setting password rules in /etc/login.defs" 2>&1 | tee -a $INSTLOG

cp -p /etc/login.defs /etc/.login.defs.$CURDATE 2>&1 | tee -a $INSTLOG

rm -rf /etc/login.defs.TMP

##SIMP##sed -e 's/PASS_MIN_LEN.*/PASS_MIN_LEN  14/g' /etc/login.defs > /etc/login.defs.TMP
##SIMP##mv -f /etc/login.defs.TMP /etc/login.defs 2>&1 | tee -a $INSTLOG

sed -e 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/g' /etc/login.defs > /etc/login.defs.TMP
mv -f /etc/login.defs.TMP /etc/login.defs 2>&1 | tee -a $INSTLOG

sed -e 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/g' /etc/login.defs > /etc/login.defs.TMP
mv -f /etc/login.defs.TMP /etc/login.defs 2>&1 | tee -a $INSTLOG

##SIMP##sed -e 's/PASS_WARN_AGE.*/PASS_WARN_AGE 14/g' /etc/login.defs > /etc/login.defs.TMP
##SIMP##mv -f /etc/login.defs.TMP /etc/login.defs 2>&1 | tee -a $INSTLOG

chmod 644 /etc/login.defs 2>&1 | tee -a $INSTLOG
chown root:root /etc/login.defs 2>&1 | tee -a $INSTLOG

echo "-- END: Setting password rules in /etc/login.defs" 2>&1 | tee -a $INSTLOG

#******************************************
# Re-writing all /etc/pam.d/(service) files
#
# Back up all first, then re-write with lockdown procedures
# Files: 
# /etc/pam.d/system-auth-ac
# /etc/pam.d/password-auth-ac
# /etc/pam.d/gdm-password
# /etc/pam.d/su
# /etc/pam.d/gdm (exists only when desktop components are installed)
# /etc/pam.d/gnome-screensaver (exists only when desktop components are installed)
# /etc/pam.d/login
# /etc/pam.d/other
# /etc/pam.d/sshd
# /etc/pam.d/sudo
#
# Back everything up
##SIMP##PAM_DIR=/etc/pam.d
##SIMP##PAM_FILES='system-auth-ac password-auth-ac gdm-password su gdm gnome-screensaver login other sshd sudo'
##SIMP##PAM_BKUP_DIR=$CURRENT_DIR/pam_backup

##SIMP##echo "-- START: Backing up all pam.d files - ignore any errors for gdm and gnome-screensaver" 2>&1 | tee -a $INSTLOG

##SIMP##mkdir -p $PAM_BKUP_DIR 2>&1 | tee -a $INSTLOG

##SIMP##for pmfiles in $PAM_FILES
##SIMP##do
##SIMP##   echo " -- attempting to back up $pmfiles" 2>&1 | tee -a $INSTLOG
##SIMP##   cp $PAM_DIR/$pmfiles $PAM_BKUP_DIR/$pmfiles.$CURDATE.pre 2>&1 | tee -a $INSTLOG
##SIMP##done

##SIMP##echo "-- END: Pam.d backup complete" 2>&1 | tee -a $INSTLOG

##SIMP##echo "-- START: Creating new pam.d files using STIG parameters" 2>&1 | tee -a $INSTLOG

###########################################
# File: /etc/pam.d/system-auth-ac
# SRG-OS-000071 RHEL-06-000056_rule CAT III (numeric)
# SRG-OS-000069 RHEL-06-000057_rule CAT III (upper case)
# SRG-OS-000266 RHEL-06-000058_rule CAT III (special char)
# SRG-OS-000070 RHEL-06-000059_rule CAT III (lower case)
# SRG-OS-000072 RHEL-06-000060_rule CAT III (differing chars)
# SRG-OS-000077 RHEL-06-000274_rule CAT II (remember 24 passwords)
# SRG-OS-999999 RHEL-06-000030_rule CAT I (remove nullok from system-auth-ac entirely)
###########################################
##SIMP##cat <<EOF > /etc/pam.d/system-auth-ac
##SIMP###%PAM-1.0
##SIMP### This file is auto-generated.
##SIMP### User changes will be destroyed the next time authconfig is run.
##SIMP##auth        required      pam_env.so
##SIMP##auth        required      pam_tally2.so deny=3 onerr=fail unlock_time=900
##SIMP##auth        sufficient    pam_unix.so nullok try_first_pass
##SIMP##auth        requisite     pam_succeed_if.so uid >= 500 quiet
##SIMP##auth        required      pam_deny.so

##SIMP##account     required      pam_tally2.so
##SIMP##account     required      pam_unix.so
##SIMP##account     sufficient    pam_localuser.so
##SIMP##account     sufficient    pam_succeed_if.so uid < 500 quiet
##SIMP##account     required      pam_permit.so

##SIMP##password    required      pam_passwdqc.so enforce=users min=disabled,disabled,disabled,disabled,14
##SIMP##password    sufficient    pam_unix.so sha512 shadow use_authtok dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=4 remember=24
##SIMP##password    required      pam_deny.so

##SIMP##session     optional      pam_keyinit.so revoke
##SIMP##session     required      pam_limits.so
##SIMP##session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
##SIMP##session     required      pam_unix.so
##SIMP##EOF
###########################################
# File: /etc/pam.d/password-auth-ac
###########################################
##SIMP##cat <<EOF > /etc/pam.d/password-auth-ac
##SIMP###%PAM-1.0
##SIMP### This file is auto-generated.
##SIMP### User changes will be destroyed the next time authconfig is run.
##SIMP##auth        required      pam_env.so
##SIMP##auth        required      pam_tally2.so deny=3 onerr=fail unlock_time=900
##SIMP##auth        sufficient    pam_unix.so nullok try_first_pass
##SIMP##auth        requisite     pam_succeed_if.so uid >= 500 quiet
##SIMP##auth        required      pam_deny.so

##SIMP##account     required      pam_unix.so
##SIMP##account     required      pam_tally2.so
##SIMP##account     sufficient    pam_localuser.so
##SIMP##account     sufficient    pam_succeed_if.so uid < 500 quiet
##SIMP##account     required      pam_permit.so

##SIMP##password    required      pam_passwdqc.so enforce=users min=disabled,disabled,disabled,disabled,14
##SIMP##password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok
##SIMP##password    required      pam_deny.so

##SIMP##session     optional      pam_keyinit.so revoke
##SIMP##session     required      pam_limits.so
##SIMP##session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
##SIMP##session     required      pam_unix.so
##SIMP##EOF
###########################################
# File: /etc/pam.d/gdm-password
# Note: To prevent root logins at the console (GUI), a line needed
# to be added to this module:
# auth       required    pam_succeed_if.so user != root quiet
###########################################
##SIMP##cat << EOF > /etc/pam.d/gdm-password
##SIMP##auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so
##SIMP##auth        substack      password-auth
##SIMP##auth        optional      pam_gnome_keyring.so

##SIMP##account     required      pam_nologin.so
##SIMP##account     include       password-auth

##SIMP##password    substack      password-auth
##SIMP##password    optional      pam_gnome_keyring.so

##SIMP##session     required      pam_selinux.so close
##SIMP##session     required      pam_loginuid.so
##SIMP##session     optional      pam_console.so
##SIMP##session     required      pam_selinux.so open
##SIMP##session     optional      pam_keyinit.so force revoke
##SIMP##session     required      pam_namespace.so
##SIMP##session     optional      pam_gnome_keyring.so auto_start
##SIMP##session     include       password-auth

##SIMP##auth       required    pam_succeed_if.so user != root quiet
##SIMP##EOF
###########################################
# File: /etc/pam.d/su
###########################################
##SIMP##cat << EOF > /etc/pam.d/su
##SIMP###%PAM-1.0
##SIMP##auth            sufficient      pam_rootok.so
##SIMP### Uncomment the following line to implicitly trust users in the "wheel" group.
##SIMP###auth           sufficient      pam_wheel.so trust use_uid
##SIMP### Uncomment the following line to require a user to be in the "wheel" group.
##SIMP##auth            required        pam_wheel.so use_uid
##SIMP##auth            include         system-auth
##SIMP##account         sufficient      pam_succeed_if.so uid = 0 use_uid quiet
##SIMP##account         include         system-auth
##SIMP##password        include         system-auth
##SIMP##session         include         system-auth
##SIMP##session         optional        pam_xauth.so
##SIMP##EOF
###########################################
# File: /etc/pam.d/gdm
###########################################
##SIMP##cat <<EOF > /etc/pam.d/gdm
##SIMP###%PAM-1.0
##SIMP##auth       required    pam_env.so
##SIMP##auth       include     system-auth
##SIMP##auth       required    pam_tally2.so deny=3 onerr=fail unlock_time=900
##SIMP##account    required    pam_nologin.so
##SIMP##account    include     system-auth
##SIMP##account    required    pam_tally2.so
##SIMP##password   include     system-auth
##SIMP##session    optional    pam_keyinit.so force revoke
##SIMP##session    include     system-auth
##SIMP##session    required    pam_loginuid.so
##SIMP##session    optional    pam_console.so
##SIMP##session    required    pam_lastlog.so silent
##SIMP##EOF
###########################################
# File: /etc/pam.d/gnome-screensaver
###########################################
##SIMP##cat <<EOF > /etc/pam.d/gnome-screensaver
##SIMP###%PAM-1.0
##SIMP##auth       include      system-auth
##SIMP##auth       required     pam_tally2.so
##SIMP##account    include      system-auth
##SIMP##account    required     pam_tally2.so
##SIMP##password   include      system-auth
##SIMP##session    include      system-auth
##SIMP##EOF
###########################################
# File: /etc/pam.d/login
########################################### 
##SIMP##cat <<EOF > /etc/pam.d/login
##SIMP###%PAM-1.0
##SIMP##auth       required     pam_securetty.so
##SIMP##auth       include      system-auth
##SIMP##auth       required     pam_tally2.so deny=3 onerr=fail unlock_time=900
##SIMP##account    required     pam_nologin.so
##SIMP##account    include      system-auth
##SIMP##account    required     pam_tally2.so
##SIMP##password   include      system-auth
##SIMP### pam_selinux.so close should be the first session rule
##SIMP##session    required     pam_selinux.so close
##SIMP##session    include      system-auth
##SIMP##session    required     pam_loginuid.so
##SIMP##session    optional     pam_console.so
##SIMP### pam_selinux.so open should only be followed by sessions to be executed in the user context
##SIMP##session    required     pam_selinux.so open
##SIMP##session    optional     pam_keyinit.so force revoke
##SIMP##EOF
###########################################
# File: /etc/pam.d/other
###########################################
##SIMP##cat <<EOF > /etc/pam.d/other
##SIMP###%PAM-1.0
##SIMP##auth     required       pam_deny.so
##SIMP##account  required       pam_deny.so
##SIMP##password required       pam_deny.so
##SIMP##session  required       pam_deny.so
##SIMP##EOF
###########################################
# File: /etc/pam.d/sshd
###########################################
##SIMP##cat <<EOF > /etc/pam.d/sshd
##SIMP###%PAM-1.0
##SIMP##auth       include      system-auth
##SIMP##auth       required     pam_tally2.so deny=3 onerr=fail unlock_time=900
##SIMP##account    required     pam_nologin.so
##SIMP##account    include      system-auth
##SIMP##account    required     pam_tally2.so per_user
##SIMP##password   include      system-auth
##SIMP##session    optional     pam_keyinit.so force revoke
##SIMP##session    include      system-auth
##SIMP##session    required     pam_loginuid.so
##SIMP##EOF
###########################################
# File: /etc/pam.d/sudo
###########################################
##SIMP##cat <<EOF > /etc/pam.d/sudo
##SIMP###%PAM-1.0
##SIMP##auth       include      system-auth
##SIMP##auth       required     pam_tally2.so deny=3 onerr=false unlock_time=900
##SIMP##account    include      system-auth
##SIMP##account    required     pam_tally2.so
##SIMP##password   include      system-auth
##SIMP##session    optional     pam_keyinit.so revoke
##SIMP##session    required     pam_limits.so
##SIMP##EOF

##SIMP##echo "-- END: New pam.d file creation complete" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000080 RHEL-06-000069_rule CAT II (require root login)
# SRG-OS-000080 RHEL-06-000070_rule CAT II (disable interactive startup)

echo "-- START: Setting root behavior for single-user mode" 2>&1 | tee -a $INSTLOG

cp -p /etc/sysconfig/init /etc/sysconfig/.init.$CURDATE 2>&1 | tee -a $INSTLOG

sed -e 's/SINGLE=\/sbin\/sushell/SINGLE=\/sbin\/sulogin/g' /etc/sysconfig/init > /etc/sysconfig/init.tmp
mv -f /etc/sysconfig/init.tmp /etc/sysconfig/init 2>&1 | tee -a $INSTLOG

##SIMP##sed -e 's/PROMPT=yes/PROMPT=no/g' /etc/sysconfig/init > /etc/sysconfig/init.tmp
##SIMP##mv -f /etc/sysconfig/init.tmp /etc/sysconfig/init 2>&1 | tee -a $INSTLOG

chown root:root /etc/sysconfig/init 2>&1 | tee -a $INSTLOG
chmod 644 /etc/sysconfig/init 2>&1 | tee -a $INSTLOG

echo "-- END: Setting root prompt for single-user mode" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000037 RHEL-06-000158_rule
# CAT II

echo "-- START: Setting audit boot parameters in grub" 2>&1 | tee -a $INSTLOG

cp -p /boot/grub/grub.conf /boot/grub/.grub.conf.$CURDATE 2>&1 | tee -a $INSTLOG

##SIMP##sed -e 's/ audit=1//g; /kernel/s/$/ audit=1/g' /boot/grub/grub.conf > /boot/grub/grub.conf.TMP
##SIMP##mv -f /boot/grub/grub.conf.TMP /boot/grub/grub.conf 2>&1 | tee -a $INSTLOG

chmod 600 /boot/grub/grub.conf 2>&1 | tee -a $INSTLOG
chown root:root /boot/grub/grub.conf 2>&1 | tee -a $INSTLOG

echo "-- END: Setting audit boot parameters in grub" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000020 RHEL-06-000198_rule CAT III

echo "-- START: Outputting SUID and SGID files to $CURRENT_DIR/REVIEW-suid-sgid-files.txt" \
2>&1 | tee -a $INSTLOG

for part in `awk '($3 == "ext2" || $3 == "ext3" || $3 == "ext4") { print $2 }' /etc/fstab`
do
   find $part -xdev -type f -perm -4000 -o -perm -2000 -print >> $CURRENT_DIR/REVIEW-suid-sgid-files.txt
done

echo "-- END: Outputting SUID and SGID files to $CURRENT_DIR/REVIEW-suid-sgid-files.txt" \
2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000109 RHEL-06-000237_rule
# CAT II

echo "-- START: Disabling root login via ssh" 2>&1 | tee -a $INSTLOG

cp -p /etc/ssh/sshd_config /etc/ssh/.sshd_config.$CURDATE 2>&1 | tee -a $INSTLOG

##SIMP##sed -e 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config > /etc/ssh/sshd_config.TMP
##SIMP##mv -f /etc/ssh/sshd_config.TMP /etc/ssh/sshd_config 2>&1 | tee -a $INSTLOG

##SIMP##sed -e 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config > /etc/ssh/sshd_config.TMP
##SIMP##mv -f /etc/ssh/sshd_config.TMP /etc/ssh/sshd_config 2>&1 | tee -a $INSTLOG

chmod 600 /etc/ssh/sshd_config 2>&1 | tee -a $INSTLOG
chown root:root /etc/ssh/sshd_config 2>&1 | tee -a $INSTLOG

echo "-- END: Disabling root login via ssh" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000120 RHEL-06-000242_rule
# CAT II

echo "-- START: Configuring Ciphers in /etc/ssh/ssh_config" 2>&1 | tee -a $INSTLOG

cp -p /etc/ssh/ssh_config /etc/ssh/.ssh_config.$CURDATE 2>&1 | tee -a $INSTLOG

sed -e 's/#   Ciphers.*/Ciphers 3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc/g' /etc/ssh/ssh_config > \
/etc/ssh/ssh_config.TMP
mv -f /etc/ssh/ssh_config.TMP /etc/ssh/ssh_config 2>&1 | tee -a $INSTLOG

chmod 600 /etc/ssh/ssh_config 2>&1 | tee -a $INSTLOG
chown root:root /etc/ssh/ssh_config 2>&1 | tee -a $INSTLOG

echo "-- END: Configuring Ciphers in /etc/ssh/ssh_config" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-999999 RHEL-06-000282_rule
# CAT II

echo "-- START: Outputting World Writable files to REVIEW-world-writable-files.txt" \
2>&1 | tee -a $INSTLOG

for part in `awk '($3 == "ext2" || $3 == "ext3" || $3 == "ext4") { print $2 }' /etc/fstab`
do
   find $part -xdev -type f -perm -0002 -print >> $CURRENT_DIR/REVIEW-world-writable-files.txt
done

echo "-- END: Outputting World Writable files to REVIEW-world-writable-files.txt" \
2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-999999 RHEL-06-000286_rule CAT I
# Note: Modification of this file satisfies the STIG but did not actually disable
# the key sequence for GDM. It disables it for headless console.
# See earlier note for this STIG entry in this script

echo "-- START: Disabling CTL-ALT-Delete function" 2>&1 | tee -a $INSTLOG

cp -f /etc/init/control-alt-delete.conf /etc/init/.control-alt-delete.conf.$CURDATE \
2>&1 | tee -a $INSTLOG

#echo "start on control-alt-delete" > /etc/init/control-alt-delete.conf
#echo "exec /usr/bin/logger -p security.info Control-Alt-Delete pressed" \
#>> /etc/init/control-alt-delete.conf

#chown root:root /etc/init/control-alt-delete.conf 2>&1 | tee -a $INSTLOG
#chmod 644 /etc/init/control-alt-delete.conf 2>&1 | tee -a $INSTLOG

# This should disable the sequence on a headless console

echo "start on control-alt-delete" > /etc/init/control-alt-delete.override
echo "exec /usr/bin/logger -p security.info Control-Alt-Delete pressed" \
>> /etc/init/control-alt-delete.override

chown root:root /etc/init/control-alt-delete.override 2>&1 | tee -a $INSTLOG
chmod 644 /etc/init/control-alt-delete.override 2>&1 | tee -a $INSTLOG
chattr +i /etc/init/control-alt-delete.override 2>&1 | tee -a $INSTLOG

echo "-- END: Disabling CTL-ALT-Delete function" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000085 RHEL-06-000300_rule
# CAT III

echo "-- START: Outputting unowned files to REVIEW-unowned-files.txt" 2>&1 | tee -a $INSTLOG

for part in `awk '($3 == "ext2" || $3 == "ext3" || $3 == "ext4") { print $2 }' /etc/fstab`
do
   find -xdev -nouser -print >> $CURRENT_DIR/REVIEW-unowned-files.txt
done

echo "-- END: Outputting unowned files to REVIEW-unowned-files.txt" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000085 RHEL-06-000301_rule
# CAT III

echo "-- START: Outputting files with no group to REVIEW-files-without-groups.txt" 2>&1 | tee -a $INSTLOG

for part in `awk '($3 == "ext2" || $3 == "ext3" || $3 == "ext4") { print $2 }' /etc/fstab`
do
   find -xdev -nogroup -print >> $CURRENT_DIR/REVIEW-files-without-groups.txt
done

echo "-- END: Outputting files with no group to REVIEW-files-without-groups.txt" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000034 RHEL-06-000315_rule CAT II
# SRG-OS-000195 RHEL-06-000317_rule CAT III
 
echo "-- START: Disabling various USB and bluetooth options" 2>&1 | tee -a $INSTLOG

if [ -f /etc/modprobe.conf ]; then 
  cp -p  /etc/modprobe.conf /etc/.modprobe.conf.$CURDATE 2>&1 | tee -a $INSTLOG
fi

echo "#Lockdown bluetooth devices" > /etc/modprobe.d/no-bluetooth.conf
echo "install net-pf-31 /bin/true" >> /etc/modprobe.d/no-bluetooth.conf
echo "install bluetooth /bin/true" >> /etc/modprobe.d/no-bluetooth.conf
chmod 644 /etc/modprobe.d/no-bluetooth.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/modprobe.d/no-bluetooth.conf 2>&1 | tee -a $INSTLOG

echo "alias net-pf-31 off" >> /etc/modprobe.conf
chmod 644 /etc/modprobe.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/modprobe.conf 2>&1 | tee -a $INSTLOG

echo "#Lockdown USB Devices" > /etc/modprobe.d/no-usb.conf
echo "install usb-storage /bin/true" >> /etc/modprobe.d/no-usb.conf
chmod 644 /etc/modprobe.d/no-usb.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/modprobe.d/no-usb.conf 2>&1 | tee -a $INSTLOG

echo "#Lockdown Firewire Devices" > /etc/modprobe.d/no-firewire.conf
echo "install firewire_ohci /bin/true" >> /etc/modprobe.d/no-firewire.conf
chmod 644 /etc/modprobe.d/no-firewire.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/modprobe.d/no-firewire.conf 2>&1 | tee -a $INSTLOG

echo "-- END: Disabling various USB and bluetooth options" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-999999 RHEL-06-000342_rule CAT II (bashrc)
# SRG-OS-999999 RHEL-06-000343_rule CAT II (csh.cshrc)
# SRG-OS-999999 RHEL-06-000344_rule CAT II (profile)

echo "-- START: Set the umasks for all users to 077" 2>&1 | tee -a $INSTLOG

cp -p /etc/bashrc /etc/.bashrc.$CURDATE 2>&1 | tee -a $INSTLOG
cp -p /etc/profile /etc/.profile.$CURDATE 2>&1 | tee -a $INSTLOG
cp -p /etc/csh.cshrc /etc/.csh.cshrc.$CURDATE 2>&1 | tee -a $INSTLOG

sed -e 's/umask .*/umask 077/g' /etc/bashrc > /etc/bashrc.TMP
mv -f /etc/bashrc.TMP /etc/bashrc 2>&1 | tee -a $INSTLOG
chown root:root /etc/bashrc 2>&1 | tee -a $INSTLOG
chmod 444 /etc/bashrc 2>&1 | tee -a $INSTLOG

sed -e 's/umask .*/umask 077/g' /etc/profile > /etc/profile.TMP
mv -f /etc/profile.TMP /etc/profile 2>&1 | tee -a $INSTLOG
chown root:root /etc/profile 2>&1 | tee -a $INSTLOG
chmod 444 /etc/profile 2>&1 | tee -a $INSTLOG
echo "TMOUT=900; export TMOUT" >> /etc/profile

sed -e 's/umask .*/umask 077/g' /etc/csh.cshrc > /etc/csh.cshrc.TMP
mv -f /etc/csh.cshrc.TMP /etc/csh.cshrc 2>&1 | tee -a $INSTLOG
chown root:root /etc/csh.cshrc 2>&1 | tee -a $INSTLOG
chmod 444 /etc/csh.cshrc 2>&1 | tee -a $INSTLOG

# This is not a STIG but recommended

cp -p /etc/skel/.bash_logout /etc/skel/.bash_logout.$CURDATE 2>&1 | tee -a $INSTLOG
cp -p /etc/skel/.bash_profile /etc/skel/.bash_profile.$CURDATE 2>&1 | tee -a $INSTLOG
cp -p /etc/skel/.bashrc /etc/skel/.bashrc.$CURDATE 2>&1 | tee -a $INSTLOG

if [ -f /etc/skel/.kshrc ]; then
  cp -p /etc/skel/.kshrc /etc/skel/.kshrc.$CURDATE 2>&1 | tee -a $INSTLOG
  sed -e 's/umask .*/umask 077/g' /etc/skel/.kshrc > /etc/skel/.kshrc.TMP
  mv -f /etc/skel/.kshrc.TMP /etc/skel/.kshrc 2>&1 | tee -a $INSTLOG
  chmod 0600 /etc/skel/.kshrc 2>&1 | tee -a $INSTLOG
fi

sed -e 's/umask .*/umask 077/g' /etc/skel/.bash_logout > /etc/skel/.bash_logout.TMP
mv -f /etc/skel/.bash_logout.TMP /etc/skel/.bash_logout 2>&1 | tee -a $INSTLOG
chmod 0600 /etc/skel/.bash_logout 2>&1 | tee -a $INSTLOG

sed -e 's/umask .*/umask 077/g' /etc/skel/.bash_profile > /etc/skel/.bash_profile.TMP
mv -f /etc/skel/.bash_profile.TMP /etc/skel/.bash_profile 2>&1 | tee -a $INSTLOG
chmod 0600 /etc/skel/.bash_profile 2>&1 | tee -a $INSTLOG

sed -e 's/umask .*/umask 077/g' /etc/skel/.bashrc > /etc/skel/.bashrc.TMP
mv -f /etc/skel/.bashrc.TMP /etc/skel/.bashrc 2>&1 | tee -a $INSTLOG
chmod 0600 /etc/skel/.bashrc 2>&1 | tee -a $INSTLOG

echo "-- END: Set the umasks for all users to 077" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit for best practice
# Override pathmunge and set root's path in /etc/profile

echo "-- START: Setting root's path in /etc/profile" 2>&1 | tee -a $INSTLOG

cp -p /etc/profile /etc/.profile.$CURDATE 2>&1 | tee -a $INSTLOG
echo " " >> /etc/profile
echo "# Setting root's path" >> /etc/profile
echo "if [ \"\$EUID\" == \"0\" ]; then" >> /etc/profile
echo "  PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin" >> /etc/profile
echo "  export PATH" >> /etc/profile
echo "fi" >> /etc/profile

chown root:root /etc/profile 2>&1 | tee -a $INSTLOG
chmod 444 /etc/profile 2>&1 | tee -a $INSTLOG

echo "-- END: Setting root's path in /etc/profile" 2>&1 | tee -a $INSTLOG

#******************************************

# Multiple audits for services from STIGs and DLB 2.x
# Note: Certain services are not present on the base build but may show up 
# later after add-on packages (i.e. ISCSI services)

echo "-- START: Disabling unnecessary services - ignore errors as some are not present" 2>&1 | tee -a $INSTLOG

$CHKCONFIG xinetd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG avahi-daemon off 2>&1 | tee -a $INSTLOG
$CHKCONFIG bluetooth off 2>&1 | tee -a $INSTLOG
$CHKCONFIG cups off 2>&1 | tee -a $INSTLOG
$CHKCONFIG cups-config-daemon off 2>&1 | tee -a $INSTLOG
$CHKCONFIG irda off 2>&1 | tee -a $INSTLOG
$CHKCONFIG lm_sensors off 2>&1 | tee -a $INSTLOG
$CHKCONFIG portmap off 2>&1 | tee -a $INSTLOG
$CHKCONFIG rpcgssd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG rpcidmapd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG rpcsvcgssd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG sendmail off 2>&1 | tee -a $INSTLOG
$CHKCONFIG setroubleshoot off 2>&1 | tee -a $INSTLOG
$CHKCONFIG yum-updatesd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG atd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG autofs off 2>&1 | tee -a $INSTLOG
$CHKCONFIG firstboot off 2>&1 | tee -a $INSTLOG
$CHKCONFIG hidd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG hplip off 2>&1 | tee -a $INSTLOG
$CHKCONFIG jexec off 2>&1 | tee -a $INSTLOG
$CHKCONFIG mdmonitor off 2>&1 | tee -a $INSTLOG
$CHKCONFIG microcode_ctl off 2>&1 | tee -a $INSTLOG
$CHKCONFIG pcscd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG readahead_early off 2>&1 | tee -a $INSTLOG
$CHKCONFIG readahead_later off 2>&1 | tee -a $INSTLOG
$CHKCONFIG rhnsd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG ypbind off 2>&1 | tee -a $INSTLOG
$CHKCONFIG postfix off 2>&1 | tee -a $INSTLOG
$CHKCONFIG snmpd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG snmptrapd off 2>&1 | tee -a $INSTLOG
$CHKCONFIG iscsi off 2>&1 | tee -a $INSTLOG
$CHKCONFIG iscsid off 2>&1 | tee -a $INSTLOG
$CHKCONFIG NetworkManager off 2>&1 | tee -a $INSTLOG

## Additions 5 Aug 2013 from CTA ##

$SERVICE netfs stop 2>&1 | tee -a $INSTLOG
$CHKCONFIG netfs off 2>&1 | tee -a $INSTLOG

## End additions

echo "-- END: Disabling unnecessary services - ignore errors as some are not present" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit from DLB 2.x
# Installs consent banner

echo "-- START: Installing and configuring consent banners" 2>&1 | tee -a $INSTLOG

if [ -d /etc/gdm/PostLogin ]; then
   cp -f $CURRENT_DIR/CONSENT/Default /etc/gdm/PostLogin/Default  2>&1 | tee -a $INSTLOG
   chmod 755 /etc/gdm/PostLogin/Default  2>&1 | tee -a $INSTLOG
   chown root:root /etc/gdm/PostLogin/Default  2>&1 | tee -a $INSTLOG
fi

mv -f /etc/issue /etc/.issue.$CURDATE 2>&1 | tee -a $INSTLOG
cp -f $CURRENT_DIR/CONSENT/issue /etc/issue 2>&1 | tee -a $INSTLOG
chmod 444 /etc/issue 2>&1 | tee -a $INSTLOG
chown root:root /etc/issue 2>&1 | tee -a $INSTLOG

if [ -f /etc/issue.net ]; then
  mv -f /etc/issue.net /etc/.issue.net.$CURDATE 2>&1 | tee -a $INSTLOG
  cat /dev/null > /etc/issue.net
  chmod 644 /etc/issue.net 2>&1 | tee -a $INSTLOG
  chown root:root /etc/issue.net 2>&1 | tee -a $INSTLOG
fi

cp -f $CURRENT_DIR/CONSENT/z_consent.sh /etc/profile.d/z_consent.sh 2>&1 | tee -a $INSTLOG
chmod 555 /etc/profile.d/z_consent.sh 2>&1 | tee -a $INSTLOG
chown root:root /etc/profile.d/z_consent.sh 2>&1 | tee -a $INSTLOG

cp -f $CURRENT_DIR/CONSENT/z_consent.csh /etc/profile.d/z_consent.csh 2>&1 | tee -a $INSTLOG
chmod 555 /etc/profile.d/z_consent.csh 2>&1 | tee -a $INSTLOG
chown root:root /etc/profile.d/z_consent.csh 2>&1 | tee -a $INSTLOG

cp -f $CURRENT_DIR/CONSENT/consent.sh /usr/sbin/consent.sh 2>&1 | tee -a $INSTLOG
chmod 555 /usr/sbin/consent.sh 2>&1 | tee -a $INSTLOG
chown root:root /usr/sbin/consent.sh 2>&1 | tee -a $INSTLOG

echo "-- END: Installing and configuring consent banners" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit from DLB 2.x
# Sets audit rules based on SecSCN v6.3 results from 17 Apr 2013

##SIMP##echo "-- START: Setting audit rules in $AUDIT_DIR/audit.rules" 2>&1 | tee -a $INSTLOG

##SIMP##mv -f $AUDIT_DIR/audit.rules $AUDIT_DIR/.audit.rules.$CURDATE 2>&1 | tee -a $INSTLOG

# determine audit rules file to use
##SIMP##rpm -qv xorg-x11-server-Xorg > /dev/null 2>&1
##SIMP##if [ $? != "0" ]; then
##SIMP##   cp -f $CURRENT_DIR/AUDIT/audit.rules.base $AUDIT_DIR/audit.rules 2>&1 | tee -a $INSTLOG
##SIMP##else
##SIMP##    cp -f $CURRENT_DIR/AUDIT/audit.rules.desktop $AUDIT_DIR/audit.rules 2>&1 | tee -a $INSTLOG
##SIMP##fi

##SIMP##chmod 400 $AUDIT_DIR/audit.rules 2>&1 | tee -a $INSTLOG
##SIMP##chown root:root $AUDIT_DIR/audit.rules 2>&1 | tee -a $INSTLOG

##SIMP##echo "-- END: Setting audit rules in $AUDIT_DIR/audit.rules" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit from DLB 2.x
# Configure /etc/logrotate.conf file

echo "-- START: Setting logrotate rules in /etc/logrotate.conf" 2>&1 | tee -a $INSTLOG

cp -p /etc/logrotate.conf /etc/.logrotate.conf.$CURDATE 2>&1 | tee -a $INSTLOG

sed -e '/^dateformat/d' /etc/logrotate.conf > /etc/logrotate.conf.TMP
mv -f /etc/logrotate.conf.TMP /etc/logrotate.conf 2>&1 | tee -a $INSTLOG

sed -e 's/^dateext/&\ndateformat -%Y%m%d.%s/g' /etc/logrotate.conf > /etc/logrotate.conf.TMP
mv -f /etc/logrotate.conf.TMP /etc/logrotate.conf 2>&1 | tee -a $INSTLOG

sed -e 's/^rotate .*/rotate 90/g' /etc/logrotate.conf  > /etc/logrotate.conf.TMP
mv -f /etc/logrotate.conf.TMP /etc/logrotate.conf 2>&1 | tee -a $INSTLOG

sed -e 's/^#compress/compress/g' /etc/logrotate.conf  > /etc/logrotate.conf.TMP
mv -f /etc/logrotate.conf.TMP /etc/logrotate.conf 2>&1 | tee -a $INSTLOG

chmod 644 /etc/logrotate.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/logrotate.conf 2>&1 | tee -a $INSTLOG

echo "-- END: Setting logrotate rules in /etc/logrotate.conf" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit from DLB 2.x
# Add auditd.cron to /etc/cron.daily to compress audit.log files

echo "-- START: Adding auditd.cron file to /etc/cron.daily" 2>&1 | tee -a $INSTLOG

cp -f $CURRENT_DIR/AUDIT/auditd.cron /etc/cron.daily/auditd.cron 2>&1 | tee -a $INSTLOG
chmod 700 /etc/cron.daily/auditd.cron 2>&1 | tee -a $INSTLOG
chown root:root /etc/cron.daily/auditd.cron 2>&1 | tee -a $INSTLOG

echo "-- END: Adding auditd.cron file to /etc/cron.daily" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit from DLB 2.x
# Configure /etc/sudoers to enable wheel group

echo "-- START: Enabling wheel group in /etc/sudoers" 2>&1 | tee -a $INSTLOG

cp -p /etc/sudoers /etc/.sudoers.$CURDATE 2>&1 | tee -a $INSTLOG

sed -e 's/#[[:blank:]]%wheel[[:blank:]]ALL=(ALL)[[:blank:]]ALL/%wheel ALL=(ALL) ALL/g' /etc/sudoers > \
/etc/sudoers.TMP 2>&1 | tee -a $INSTLOG

mv -f /etc/sudoers.TMP /etc/sudoers 2>&1 | tee -a $INSTLOG

chown root:root /etc/sudoers 2>&1 | tee -a $INSTLOG
chmod 400 /etc/sudoers 2>&1 | tee -a $INSTLOG

echo "-- END: Enabling wheel group in /etc/sudoers" 2>&1 | tee -a $INSTLOG

#******************************************

# Non-audit from DLB 2.x

echo "-- START: Setting password rules in /etc/libuser.conf" 2>&1 | tee -a $INSTLOG

cp -p /etc/libuser.conf /etc/.libuser.conf.$CURDATE 2>&1 | tee -a $INSTLOG

# STIG does not have this in the libuser.conf file, so we are adding it.
sed -e 's/# LU_SHADOWINACTIVE.*/LU_SHADOWINACTIVE = -1/g' /etc/libuser.conf > /etc/libuser.conf.TMP
mv -f /etc/libuser.conf.TMP /etc/libuser.conf 2>&1 | tee -a $INSTLOG

sed -e 's/# LU_SHADOWMIN.*/LU_SHADOWMIN = 1/g' /etc/libuser.conf > /etc/libuser.conf.TMP
mv -f /etc/libuser.conf.TMP /etc/libuser.conf 2>&1 | tee -a $INSTLOG

sed -e 's/# LU_SHADOWMAX.*/LU_SHADOWMAX = 60/g' /etc/libuser.conf > /etc/libuser.conf.TMP
mv -f /etc/libuser.conf.TMP /etc/libuser.conf 2>&1 | tee -a $INSTLOG

sed -e 's/# LU_SHADOWWARNING.*/LU_SHADOWWARNING = 14/g' /etc/libuser.conf > /etc/libuser.conf.TMP
mv -f /etc/libuser.conf.TMP /etc/libuser.conf 2>&1 | tee -a $INSTLOG

chmod 644 /etc/libuser.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/libuser.conf 2>&1 | tee -a $INSTLOG

echo "-- END: Setting password rules in /etc/libuser.conf" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit from DLB 2.x

echo "-- START: Setting permissions on various iptables files" 2>&1 | tee -a $INSTLOG

if [ -f /etc/rc.d/init.d/iptables ]
then
   chmod go-rwx /etc/rc.d/init.d/iptables 2>&1 | tee -a $INSTLOG
fi

if [ -f /etc/rc.d/init.d/ip6tables ]
then
   chmod go-rwx /etc/rc.d/init.d/ip6tables 2>&1 | tee -a $INSTLOG
fi

if [ -f /sbin/iptables ]
then
   chmod go-rwx /sbin/iptables 2>&1 | tee -a $INSTLOG
fi

if [ -f /usr/share/logwatch/scripts/services/iptables ]
then
   chmod go-rwx /usr/share/logwatch/scripts/services/iptables 2>&1 | tee -a $INSTLOG
fi

echo "-- END: Setting permissions on various iptables files" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit from DLB 2.x
# Sets base port rules for new build
# Ports 1002/3001 are for HPSA agent

echo "-- START: Configuring basic iptables rules" 2>&1 | tee -a $INSTLOG

# Unload any live rules (none should be present but this ensures that)
if [ -f /etc/sysconfig/iptables ]
then
   echo " -- Found live iptables configuration...clearing this out" 2>&1 | tee -a $INSTLOG
   mv -f /etc/sysconfig/iptables /etc/sysconfig/.iptables.live.$CURDATE 2>&1 | tee -a $INSTLOG
   $SERVICE iptables restart 2>&1 | tee -a $INSTLOG
fi

$IPTABLES -P INPUT DROP 2>&1 | tee -a $INSTLOG
$IPTABLES -A INPUT -d 127.0.0.0/8 -i !lo -j DROP 2>&1 | tee -a $INSTLOG
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>&1 | tee -a $INSTLOG
$IPTABLES -A INPUT -p icmp -j ACCEPT 2>&1 | tee -a $INSTLOG
$IPTABLES -A INPUT -i lo -j ACCEPT 2>&1 | tee -a $INSTLOG
$IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -m comment --comment "SSH port" -j ACCEPT 2>&1 | tee -a $INSTLOG
$IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp -m multiport --dports 1002,3001 -m comment --comment "HPSA ports" -j ACCEPT 2>&1 | tee -a $INSTLOG
$IPTABLES -A FORWARD -j REJECT --reject-with icmp-host-prohibited 2>&1 | tee -a $INSTLOG

$SERVICE iptables save 2>&1 | tee -a $INSTLOG
$SERVICE iptables restart 2>&1 | tee -a $INSTLOG

chmod 600 /etc/sysconfig/iptables 2>&1 | tee -a $INSTLOG
chown root:root /etc/sysconfig/iptables 2>&1 | tee -a $INSTLOG

echo "-- END: Configuring basic iptables rules" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Ensuring only root can execute certain administrative tools

echo "-- START: Applying strict permissions to admin tools" 2>&1 | tee -a $INSTLOG

##SIMP##chmod 700 /bin/traceroute 2>&1 | tee -a $INSTLOG
chmod 700 /bin/tracepath 2>&1 | tee -a $INSTLOG
chmod 700 /bin/tracepath6 2>&1 | tee -a $INSTLOG
##SIMP##chmod 700 /usr/bin/strace 2>&1 | tee -a $INSTLOG
##SIMP##chmod 700 /usr/sbin/tcpdump 2>&1 | tee -a $INSTLOG

echo "-- END: Applying strict permissions to admin tools" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Locking down certain directories

echo "-- START: Applying permissions to dirs and files - ignore errors as some may not be present" 2>&1 | tee -a $INSTLOG

if [ -d /var/crash ]
then
   chmod go-rwx /var/crash 2>&1 | tee -a $INSTLOG
fi

if [ -d /var/www/usage ]
then
   chmod go-rwx /var/www/usage 2>&1 | tee -a $INSTLOG
fi

find /usr/share/man -type f -not -perm 644 -exec chmod go+r-wx {} \;
find /usr/share/doc -type f -exec chmod 644 {} \;
find /etc/cron.*/ -type f -exec chmod go-rwx {} \;

chmod 600 /etc/crontab 2>&1 | tee -a $INSTLOG
chmod 700 /usr/share/logwatch/scripts/logwatch.pl 2>&1 | tee -a $INSTLOG
chmod 600 /etc/sysctl.conf 2>&1 | tee -a $INSTLOG
chmod 600 /var/log/maillog 2>&1 | tee -a $INSTLOG
chmod 640 /etc/security/access.conf 2>&1 | tee -a $INSTLOG
chmod 0444 /etc/ntp.conf 2>&1 | tee -a $INSTLOG
chmod 640 /var/log/*.log 2>&1 | tee -a $INSTLOG
chown -R root:sys /etc/snmp 2>&1 | tee -a $INSTLOG
chmod 750 /etc/snmp 2>&1 | tee -a $INSTLOG
chmod 640 /etc/snmp/snmpd.conf 2>&1 | tee -a $INSTLOG
chmod 640 /etc/snmp/snmptrapd.conf 2>&1 | tee -a $INSTLOG
chmod 400 /etc/audit/audit.rules 2>&1 | tee -a $INSTLOG

## Additions 5 Aug 2013 from CTA ##

chmod 750 /etc/security 2>&1 | tee -a $INSTLOG
chmod -R o-w /opt/* 2>&1 | tee -a $INSTLOG
chmod -R o-w /home/* 2>&1 | tee -a $INSTLOG
chmod -R o-w /root/* 2>&1 | tee -a $INSTLOG

## End additions

## Additions 15 Oct 2013 from CTA ##
# SRG-OS-000206 V-38623: Lock down ownership of /var/log/cups

chown root:root /var/log/cups 2>&1 | tee -a $INSTLOG
chmod 700 /var/log/cups 2>&1 | tee -a $INSTLOG

## End additions

echo "-- END: Applying strict permissions to directories and files" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Configuring TCP Wrappers

echo "-- START: Configuring TCP Wrappers" 2>&1 | tee -a $INSTLOG

# Overwriting any previous as these should not be present on a new build
echo "ALL: ALL" > /etc/hosts.deny
echo "sshd: ALL" > /etc/hosts.allow

echo "-- END: Configuring TCP Wrappers" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Deleting unneeded accounts

echo "-- START: Deleting unnecessary user accounts" 2>&1 | tee -a $INSTLOG

cp -p /etc/passwd /etc/.passwd.$CURDATE 2>&1 | tee -a $INSTLOG
cp -p /etc/shadow /etc/.shadow.$CURDATE 2>&1 | tee -a $INSTLOG
cp -p /etc/group /etc/.group.$CURDATE 2>&1 | tee -a $INSTLOG

for i in shutdown halt games operator ftp gopher
do
    echo " --Found $i, deleting this user" 2>&1 | tee -a $INSTLOG
    userdel $i 2>&1 | tee -a $INSTLOG
done

echo "-- END: Deleting unnecessary user accounts" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Restricting cron

echo "-- START: Restricting cron" 2>&1 | tee -a $INSTLOG

#No one gets to run cron jobs unless we say they can
touch /etc/cron.allow 2>&1 | tee -a $INSTLOG
chmod 600 /etc/cron.allow 2>&1 | tee -a $INSTLOG
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny

#No one gets to run at jobs unless we say they can
touch /etc/at.allow 2>&1 | tee -a $INSTLOG
chmod 600 /etc/at.allow 2>&1 | tee -a $INSTLOG
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

echo "-- END: Restricting cron" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Setting ACLs to ensure future yum works for non-root users

echo "-- START: Setting ACLs on /var/lib/yum" 2>&1 | tee -a $INSTLOG

if [ -d /var/lib/yum ]
then
  /usr/bin/setfacl -R -d -m o:rx /var/lib/yum
else
  echo " " 2>&1 | tee -a $INSTLOG
  echo "/var/lib/yum not found...skipping setfacl" 2>&1 | tee -a $INSTLOG
  echo " " 2>&1 | tee -a $INSTLOG
fi

echo "-- END: Setting ACLs on /var/lib/yum" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Disable NetworkManager for all NICs

echo "-- START: Disabling NetworkManager for all NICs" 2>&1 | tee -a $INSTLOG

mkdir -p $NETWORK_BKUP_DIR 2>&1 | tee -a $INSTLOG

for file in $NETWORK_DIR/ifcfg-eth*; do
   tmp_file=`/bin/basename $file`

   cp -p $NETWORK_DIR/$tmp_file $NETWORK_BKUP_DIR/$tmp_file.$CURDATE.pre 2>&1 | tee -a $INSTLOG

   sed -e 's/^NM_CONTROLLED.*/NM_CONTROLLED="no"/' $NETWORK_DIR/$tmp_file > $NETWORK_DIR/$tmp_file.TMP
   mv -f $NETWORK_DIR/$tmp_file.TMP $NETWORK_DIR/$tmp_file 2>&1 | tee -a $INSTLOG
   chmod 644 $NETWORK_DIR/$tmp_file 2>&1 | tee -a $INSTLOG
   chown root:root $NETWORK_DIR/$tmp_file 2>&1 | tee -a $INSTLOG
done

echo "-- END: Disabling NetworkManager for all NICs" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
## Additions 5 Aug 2013 from CTA ##

echo "-- START: Disabling password caching in /etc/sudoers" 2>&1 | tee -a $INSTLOG

cp -p /etc/sudoers /etc/.sudoers.$CURDATE 2>&1 | tee -a $INSTLOG

echo " " >> /etc/sudoers
echo "## Disable password caching" >> /etc/sudoers
echo "Defaults timestamp_timeout = 0" >> /etc/sudoers

echo "-- END: Disabling password caching in /etc/sudoers" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
## Additions 29 Aug 2013 from HSC ##
## Corrects library fingerprint error on non-desktop build versions ##
## Commented this routine 10 Sept 2013 due to authconfig modifying files in /etc/pam.d 
## post configuration

#echo "-- START: Disabling fingerprint on non-desktop build versions" 2>&1 | tee -a $INSTLOG
#
#/usr/sbin/authconfig --disablefingerprint --update 2>&1 | tee -a $INSTLOG
#
#echo "-- END: Disabling fingerprint on non-desktop build versions" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-999999 V-38542
# Updated 15 Oct 2013
# Post-CTA security item: Set reverse patch IPv4 filter

echo "-- START: Setting IPv4 reverse path filter" 2>&1 | tee -a $INSTLOG

cp -p /etc/sysctl.conf /etc/.sysctl.conf.$CURDATE 2>&1 | tee -a $INSTLOG

if [ "`grep net.ipv4.conf.all.rp_filter /etc/sysctl.conf`" ]; then
  cat /etc/sysctl.conf | grep -v "net.ipv4.conf.all.rp_filter" > /etc/sysctl.conf.TMP
  mv -f /etc/sysctl.conf.TMP /etc/sysctl.conf 2>&1 | tee -a $INSTLOG
  echo "net.ipv4.conf.all.rp_filter= 1" >> /etc/sysctl.conf
  chmod 600 /etc/sysctl.conf 2>&1 | tee -a $INSTLOG
  chown root:root /etc/sysctl.conf 2>&1 | tee -a $INSTLOG
else
  echo "net.ipv4.conf.all.rp_filter= 1" >> /etc/sysctl.conf
  chmod 600 /etc/sysctl.conf 2>&1 | tee -a $INSTLOG
  chown root:root /etc/sysctl.conf 2>&1 | tee -a $INSTLOG
fi

echo "-- END: Setting IPv4 reverse path filter" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000096 V-38515
# Updated 15 Oct 2013
# Post-CTA security item: Disable Stream Control Transmission Protocol

echo "-- START: Disabling SCTP" 2>&1 | tee -a $INSTLOG

echo "#Lockdown SCTP" > /etc/modprobe.d/no-sctp.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/no-sctp.conf
chmod 644 /etc/modprobe.d/no-sctp.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/modprobe.d/no-sctp.conf 2>&1 | tee -a $INSTLOG

echo "-- END: Disabling SCTP" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000096 V-38517
# Updated 15 Oct 2013
# Post-CTA security item: Disable Transparent Inter-Process Comm protocol

echo "-- START: Disabling TIPC" 2>&1 | tee -a $INSTLOG

echo "#Lockdown TIPC" > /etc/modprobe.d/no-tipc.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/no-tipc.conf
chmod 644 /etc/modprobe.d/no-tipc.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/modprobe.d/no-tipc.conf 2>&1 | tee -a $INSTLOG

echo "-- END: Disabling TIPC" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-000096 V-38514
# Updated 15 Oct 2013
# Post-CTA security item: Disable Datagram Congestion Control Protocol

echo "-- START: Disabling DCCP" 2>&1 | tee -a $INSTLOG

echo "#Lockdown DCCP" > /etc/modprobe.d/no-dccp.conf
echo "install dccp /bin/true" >> /etc/modprobe.d/no-dccp.conf
chmod 644 /etc/modprobe.d/no-dccp.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/modprobe.d/no-dccp.conf 2>&1 | tee -a $INSTLOG

echo "-- END: Disabling DCCP" 2>&1 | tee -a $INSTLOG

#******************************************
# SRG-OS-00002 V-38684
# Updated 15 Oct 2013
# Post-CTA security item: Limit users to 10 simultaneous system logins

echo "-- START: Limit users to 10 simultaneous system logins" 2>&1 | tee -a $INSTLOG

cp -p /etc/security/limits.conf /etc/security/.limits.conf.$CURDATE 2>&1 | tee -a $INSTLOG

sed -e 's/# End of file.*/*     hard   maxlogins   10\n# End of file/g' /etc/security/limits.conf > /etc/security/limits.conf.tmp
mv -f /etc/security/limits.conf.tmp /etc/security/limits.conf 2>&1 | tee -a $INSTLOG
chmod 644 /etc/security/limits.conf 2>&1 | tee -a $INSTLOG
chown root:root /etc/security/limits.conf 2>&1 | tee -a $INSTLOG

echo "-- END: Limit users to 10 simultaneous system logins" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Create default maintenance account
# Updated with sha512 version 29 Aug 2013

echo "-- START: Creating default login account: $ADMUSER" 2>&1 | tee -a $INSTLOG

#$USERADD -G wheel -p '$1$7lhq73Xw$SOFNEo1yNyCrWvM31cWMV.' $ADMUSER 2>&1 | tee -a $INSTLOG
$USERADD -G wheel -p '$6$KA28.nm9$ZtYl9mHLur9iAjz..NbuomlGF3q2/McG9WK433TJTKDkVZWtkUeOYCF6bvasUcBVfCq8HqOcuHDmJl7TtkQOr/' $ADMUSER 2>&1 | tee -a $INSTLOG

#modify maintenance account to never expire
$CHAGE -M -1 $ADMUSER 2>&1 | tee -a $INSTLOG

echo "-- END: Creating default login account: $ADMUSER" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Setting root to not expire

echo "-- START: Setting root account parameters" 2>&1 | tee -a $INSTLOG

#modify super account to never expire
$CHAGE -M -1 $SUPER 2>&1 | tee -a $INSTLOG

echo "-- END: Setting root account parameters" 2>&1 | tee -a $INSTLOG

#******************************************
# Non-audit
# Version stamping configuration

echo "-- START: Writing version stamp to /etc/icgc-release" 2>&1 | tee -a $INSTLOG

if [ -f /etc/icgc-release ]; then
  mv /etc/icgc-release /etc/.icgc-release.$CURDATE \
  2>&1 | tee -a $INSTLOG
fi

echo "ICGC Build: 1.0" > /etc/icgc-release
chmod 644 /etc/icgc-release 2>&1 | tee -a $INSTLOG
chown root:root /etc/icgc-release 2>&1 | tee -a $INSTLOG

echo "-- END: Writing version stamp to /etc/icgc-release" 2>&1 | tee -a $INSTLOG

#******************************************
# Turn McAfee Nails back on if present

# Start nails back up
/sbin/chkconfig nails > /dev/null 2>&1
if [ $? -eq "0" ]; then
  /sbin/service nails start 2>&1 | tee -a $INSTLOG
fi

#******************************************
echo " " 2>&1 | tee -a $INSTLOG
echo "System security configuration complete on `/bin/date`" 2>&1 | tee -a $INSTLOG
echo " " 2>&1 | tee -a $INSTLOG
echo "$CURDATE | $OSVERSION | $VERSION | Completed DIA core security layer" >> /etc/.icgc-cm.log
#******************************************
