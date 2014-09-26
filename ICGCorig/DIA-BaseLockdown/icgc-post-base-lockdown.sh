#!/bin/bash

AFFIL_VERSION="2011.3-12.dia.v1.0.dia.base"
PATH=$PATH:/sbin:/usr/sbin:/bin:/sbin
export PATH
CURRENT_DIR=`/usr/bin/dirname $0`
CURDATE=`date +%Y%m%d-%H%M%S`
LOGFILE=$CURRENT_DIR/install_log.$CURDATE
INDENT="                             "
CHKCONFIG=/sbin/chkconfig
OSVERSION=`/bin/awk '{print $3}' /etc/centos-release`
VERSION=1.0

####################################################
# Begin functions
####################################################

function writeToLog {
	STRING=$1
	echo "${INDENT}${STRING}" 2>&1 | tee -a $LOGFILE
}

####################################################

function modifyVAR {
        VAR=$1
        VAL=$2
        FILE=$3
        DATE=$(date)
        # See if FIle Exists befor we try to modify it
        if [ ! -f "$FILE" ] 
        then
                echo $DATE": File/Directory $FILE Does not exist. No changes made." >> $LOGFILE
                return 4
        fi
        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink. No changes made." >> $LOGFILE
                return 2
        fi

        RES=$(/bin/sed -n '/^'"$VAR"'/I p' "$FILE")
        if [ -n "$RES" ]
        then
                echo $DATE": Updating $RES to $VAR$VAL in $FILE" >> $LOGFILE
                RES=$(sed -i '/^'"$VAR"'/I c'"$VAR""$VAL"'' "$FILE" )
                RES=$(sed -n '/^'"$VAR"'/p' "$FILE" | head -1)
                echo "$INDENT New Line is $RES" >> $LOGFILE
                return 0
        else
                echo $DATE": Adding $VAR $VAL to $FILE" >> $LOGFILE
                /bin/cat <<EOL >> "$FILE"
$VAR$VAL
EOL
        return 0
        fi

        return 1
}

####################################################

function removeTextFromLine {
        TEXT=$1
        PATTERN=$2
        FILE=$3
        DATE=$(date)
        # See if File Exists befor we try to modify it
        if [ ! -f "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 4
        fi

        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink. No changes made." >> $LOGFILE
                return 2
        fi

        LINE=$(sed -n '/'"$PATTERN"'/ p' "$FILE" | head -1)
        if [ -z "$LINE" ]
        then
                echo $DATE": A Line matching REGEXP -$PATTERN- not found in $FILE" >> $LOGFILE
                return 3
        fi

        if [[ "$LINE" =~ "$TEXT" ]]
        then
                echo $DATE": Removing $TEXT from $LINE in $FILE" >> $LOGFILE
                NEWLINE=$(echo "$LINE" |  sed 's/'"$TEXT"'//g' )
                DOWORK=$(sed -i 's/'"$LINE"'/'"$NEWLINE"'/' "$FILE" )
                NEWLINE=$(sed -n '/'"$PATTERN"'/p' "$FILE" | head -1)
                echo "$INDENT New Line is $NEWLINE" >> $LOGFILE
                return 0
        else
                echo $DATE": Text -$TEXT- not found in $LINE in $FILE" >> $LOGFILE
                return 5
        fi
        # MISC Error
        return 1
}

function addLine {
        NEWLINE=$1
        FILE=$2
        DATE=$(date)
        # See if File Exists befor we try to modify it
        if [ ! -f "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 4
        fi

        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink. No changes made." >> $LOGFILE
                return 2
        fi

        RES=$(/bin/sed -n '/'"$NEWLINE"'/I p' "$FILE" | head -1)
        if [ "$RES" != "" ]
        then
                echo $DATE": A Line matching ${NEWLINE} was found in $FILE. insert not done" >> $LOGFILE
                return 3
        else
                echo $DATE": A Line matching ${NEWLINE} was not found in $FILE. " >> $LOGFILE
                echo "\t\tAppending line to file"
                echo $NEWLINE >> $FILE
                return 0
        fi
        return 1
}

####################################################

function modifyLine {
        PATTERN=$1
        NEWLINE=$2
        FILE=$3
        DATE=$(date)
        # See if File Exists befor we try to modify it
        if [ ! -f "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 4
        fi

        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink. No changes made." >> $LOGFILE
                return 2
        fi

        RES=$(sed -n '/'"$PATTERN"'/I p' "$FILE" | head -1 )
        if [ "$RES" != "" ]
        then
                echo $DATE": Updating $RES to $NEWLINE in $FILE" >> $LOGFILE
                RES=$(sed -i '/'"$PATTERN"'/I c\'"$NEWLINE"' ' "$FILE")
                #RES=$(sed -n '/'"$NEWLINE"'/p ' "$FILE" | head -1)
                #echo "$INDENT New Line is $RES" >> $LOGFILE
                return 0
        else
                echo $DATE": A Line matching REGEX $PATTERN was not found in $FILE. Skipping Append $APPEND" >> $LOGFILE
                return 3
        fi

        return 1
}

####################################################

function deleteLine {
        PATTERN=$1
        FILE=$2
        DATE=$(date)
        # See if File Exists befor we try to modify it
        if [ ! -f "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 4
        fi

        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink. No changes made." >> $LOGFILE
                return 2
        fi

        RES=$(sed -n '/'"$PATTERN"'/I p' "$FILE" | head -1 )
        if [ "$RES" != "" ]
        then
                echo $DATE": Updating $RES deleting Line from $FILE" >> $LOGFILE
                RES=$(sed -i '/'"$PATTERN"'/I d' "$FILE")
                return 0
        else
                echo $DATE": A Line matching REGEX $PATTERN was not found in $FILE. Skipping Delete $APPEND" >> $LOGFILE
                return 3
        fi

        return 1
}

####################################################

function insertLine {
	# This function finds the line that contains a pattern, then puts a new line infront of it
        PATTERN=$1
        NEWLINE=$2
        FILE=$3
        DATE=$(date)
        # See if File Exists before we try to modify it
        if [ ! -f "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 4
        fi

        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink. No changes made." >> $LOGFILE
                return 2
        fi
	
        RES=$(/bin/sed -n '/'"$PATTERN"'/I p' "$FILE" | head -1)
        if [ "$RES" != "" ]
        then
                echo $DATE": Inserting $NEWLINE before $RES in $FILE" >> $LOGFILE
                TMP=$(/bin/sed -i '/'"$PATTERN"'/I i\'"$NEWLINE"' ' ${FILE})
                #RES=$(sed -n '/'"$PATTERN"'/p' "$FILE" | head -1)
                #echo "$INDENT New Line is $RES" >> $LOGFILE
                # Remove duplicate lines
                TMP=$(/bin/awk '!_[$0]++' "$FILE" > "${FILE}.tmp")
		cat "${FILE}.tmp" > $FILE
                return 0
        else
                echo $DATE": A Line matching REGEX $PATTERN was not found in $FILE. Skipping INSERTLINE" >> $LOGFILE
                return 3
        fi
        return 1
}

####################################################

function appendLine {
	# This function finds the line that contains a pattern, then puts a new line after it
        PATTERN=$1
        NEWLINE=$2
        FILE=$3
        DATE=$(date)
        # See if FIle Exists befor we try to modify it
        if [ ! -f "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 4
        fi

        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink. No changes made." >> $LOGFILE
                return 2
        fi

        RES=$(sed -n '/'"$PATTERN"'/I p' "$FILE" | head -1)
        if [ -n "$RES" ]
        then
                echo $DATE": Adding $NEWLINE after $RES in $FILE" >> $LOGFILE
                TMP=$(sed -i '/'"$PATTERN"'/I a\'"$NEWLINE"' ' "$FILE")
                #RES=$(sed -n '/'"$PATTERN"'/p' "$FILE" | head -1)
                #echo "$INDENT New Line is $RES" >> $LOGFILE
                # Delete Duplicate Lines
                TMP=$(sed -n 'G; s/\n/&&/; /^\([ -~]*\n\).*\n\1/d; s/\n//; h; P' "$FILE")
                return 0
        else
                echo $DATE": A Line matching REGEX $PATTERN was not found in $FILE. Skipping INSERTLINE" >> $LOGFILE
                return 3
        fi
        return 1
}

####################################################

function appendToLine {
        PATTERN=$1
        APPEND=$2
        FILE=$3
        DATE=$(date)
        if [ ! -f "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 4
        fi
        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink . No changes made." >> $LOGFILE
                return 2
        fi

        TMP=$(sed -n '/'"$PATTERN"'/p' "$FILE" )
        if [[ "$TMP" =~ "$APPEND" ]]
        then
                echo $DATE": $APPEND already exists in line identified by $PATTERN in $FILE" >> $LOGFILE
                return 0
        fi
        RES=$(sed -n '/'"$PATTERN"'/p' "$FILE" )
        if [ "$RES" != "" ]
        then
                echo $DATE": Appending $APPEND to $RES in $FILE" >> $LOGFILE
                TMP=$(sed -i '/'"$PATTERN"'/I s/$/'"$APPEND"'/' "$FILE")
                RES=$(sed -n '/'"$PATTERN"'/p' "$FILE" | head -1)
                echo "$INDENT New Line is $RES" >> $LOGFILE
                return 0
        else
                echo $DATE": A Line matching REGEX $PATTERN was not found in $FILE. Skipping Append $APPEND" >> $LOGFILE
                return 3
        fi
        # Misc Error
        return 1
}

####################################################

function prependToLine {
        PATTERN=$1
        PREPEND=$2
        FILE=$3
        DATE=$(date)
        if [ ! -f "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 4
        fi
        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink . No changes made." >> $LOGFILE
                return 2
        fi

        TMP=$(sed -n '/'"$PATTERN"'/p' "$FILE" )
        if [[ "$TMP" =~ /^"$PREPEND"/ ]]
        then
                echo $DATE": $PREPEND already exists in line identified by $PATTERN in $FILE" >> $LOGFILE
                return 0
        fi
        RES=$(sed -n '/'"$PATTERN"'/p' "$FILE" )
        if [ "$RES" != "" ]
        then
                echo $DATE": Appending $APPEND to $RES in $FILE" >> $LOGFILE
                TMP=$(sed -i '/'"$PATTERN"'/I s/^/'"$PREPEND"'/' "$FILE")
                RES=$(sed -n '/'"$PATTERN"'/p' "$FILE" | head -1)
                echo "$INDENT New Line is $RES" >> $LOGFILE
                return 0
        else
                echo $DATE": A Line matching REGEX $PATTERN was not found in $FILE. Skipping Append $APPEND" >> $LOGFILE
                return 3
        fi
        # Misc Error
        return 1
}

####################################################

function setFilePerms {
        PERM=$1
        FILE=$2
        DATE=$(date)
	if [ ! -f "$FILE" -a ! -d "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 0
        fi
        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink . No changes made." >> $LOGFILE
                return 0
        fi
        # Get current File Perms
        CUR=$(stat --printf=%a  $FILE)
        if [ -n "$CUR" ]
        then
                echo $DATE": Changed Perm on $FILE from $CUR to $PERM" >> $LOGFILE
                #echo "$INDENT undo Command: chmod $CUR $FILE" >> $LOGFILE
                RES=$(chmod $PERM $FILE >&2)
                echo "$INDENT chmod $PERM $FILE Returned: $RES : " >> $LOGFILE
		echo "$INDENT Current Perms for $FILE: $(stat --printf=%a  $FILE)" >> $LOGFILE	
                return 0
        else
                echo $DATE": File $FILE not Found." >> $LOGFILE
                return 4
        fi
        return 1
}

####################################################

function setFileOwner {
        OWNER=$1
        FILE=$2
        DATE=$(date)
	if [ ! -f "$FILE" -a ! -d "$FILE" ]
        then
                echo $DATE": File $FILE Does not exist. No changes made." >> $LOGFILE
                return 0
        fi
        if [ -h "$FILE" ]
        then
                echo $DATE": File $FILE is a symlink . No changes made." >> $LOGFILE
                return 0
        fi
        # Get current File Perms
        CUR=$(/usr/bin/stat --printf=%U:%G  $FILE)
        if [ -n "$CUR" ]
        then
                echo $DATE": Changed Owner on $FILE from $CUR to $OWNER" >> $LOGFILE
                RES=$(/bin/chown $OWNER $FILE >&2)
                echo "$INDENT chown $OWNER $FILE Returned: $RES : " >> $LOGFILE
		echo "$INDENT Current Perms for $FILE: $(/usr/bin/stat --printf=%U:%G  $FILE)" >> $LOGFILE	
                return 0
        else
                echo $DATE": File $FILE not Found." >> $LOGFILE
                return 4
        fi
        return 1
}

####################################################

function backupFile {
        COPYFILENAME=$1

	if [ -f "$COPYFILENAME" ]
	then
	  echo "--Backing up $COPYFILENAME" 2>&1 | tee -a $LOGFILE
	  cp -fp $COPYFILENAME $COPYFILENAME.affil.$CURDATE 2>&1 | tee -a $LOGFILE
	else
	  echo "--The file $COPYFILENAME was not found...could not be backed up" 2>&1 | tee -a $LOGFILE
	fi
        return 0
}









####################################################
# Begin body
####################################################

function doPasswdComplexity {
	# the following functions do not change the location of a line so they can be used in an update
	writeToLog "----------------------------------------------------------"
	writeToLog "1) Calling - doPasswdComplexity - Set passwd complexity"
	backupFile /etc/login.defs
	backupFile /etc/pam.d/password-auth-ac
	backupFile /etc/pam.d/password-auth
	backupFile /etc/pam.d/system-auth-ac
	backupFile /etc/pam.d/system-auth
	
	modifyVAR 'PASS_MIN_LEN' '     14' /etc/login.defs
	modifyVAR 'PASS_WARN_AGE' '     14' /etc/login.defs
	#
	# REL 6.X 
	modifyLine "password*[ ]*requisite*[ ]*pam_cracklib.so" "password    requisite     pam_cracklib.so try_first_pass difok=4 retry=3 minlen=14 lcredit=0 ucredit=0 dcredit=0 ocredit=0 minclass=4 maxrepeat=2 reject_username" /etc/pam.d/password-auth-ac
	modifyLine "password*[ ]*requisite*[ ]*pam_cracklib.so" "password    requisite     pam_cracklib.so try_first_pass difok=4 retry=3 minlen=14 lcredit=0 ucredit=0 dcredit=0 ocredit=0 minclass=4 maxrepeat=2 reject_username" /etc/pam.d/system-auth-ac

	# for REL 5.X (wont get changed on REL 6.x cause its a symlink and the modifyLine function bails if it encounters a symlink)
	modifyLine "password*[ ]*required*[ ]*pam_cracklib.so" "password    required       pam_cracklib.so try_first_pass difok=4 retry=3 minlen=14 lcredit=0 ucredit=0 dcredit=0 ocredit=0 minclass=4 maxrepeat=2 reject_username" /etc/pam.d/system-auth
	writeToLog " "
}

####################################################

function doFilePerms {
	#
	# 15) Setup DOD recomended File Perms
	#
	writeToLog "----------------------------------------------------------"
	writeToLog "15) Calling - doFilePerms - Setup File perms"

	setFilePerms 0600 /etc/at.deny
	setFilePerms 0600 /etc/audit/audit.rules
	setFilePerms 0600 /etc/audit/auditd.conf
	setFilePerms 0600 /etc/cron.deny
	setFilePerms 0600 /etc/inittab
	setFilePerms 0600 /etc/ntp.conf
	setFilePerms 0600 /etc/rc.d/rc.local
	setFilePerms 0600 /etc/rc.local
	setFilePerms 0600 /etc/security/console.perms
	setFilePerms 0600 /etc/skel/.bashrc
	setFilePerms 0600 /etc/sysctl.conf
	setFilePerms 0600 /root/.bash_logout
	setFilePerms 0600 /var/log/dmesg
	setFilePerms 0600 /var/log/wtmp
	setFilePerms 0640 /etc/login.defs
	setFilePerms 0640 /etc/security/access.conf

	    FILES=(`find /usr/share/doc -type f`)
	    for FILE in "${FILES[@]}"; do
	        setFilePerms 0644 ${FILE}
	    done

	    FILES=(`find /usr/share/man -type f`)
	    for FILE in "${FILES[@]}"; do
	        setFilePerms 0644 ${FILE}
	    done

	setFilePerms 0400 /etc/crontab
	setFilePerms 0400 /etc/securetty
	setFilePerms 0400 /root/.bash_profile
	setFilePerms 0400 /root/.bashrc
	setFilePerms 0400 /root/.cshrc
	setFilePerms 0400 /root/.tcshrc
	setFilePerms 0400 /var/log/lastlog
	setFilePerms 0444 /etc/bashrc
	setFilePerms 0444 /etc/csh.cshrc
	setFilePerms 0444 /etc/csh.login
	setFilePerms 0444 /etc/hosts
	setFilePerms 0444 /etc/networks
	setFilePerms 0444 /etc/services
	setFilePerms 0444 /etc/shells
	setFilePerms 0444 /etc/profile
	setFilePerms 0700 /var/log/audit
	setFilePerms 0750 /etc/cron.d
	setFilePerms 0750 /etc/cron.daily
	setFilePerms 0750 /etc/cron.hourly
	setFilePerms 0750 /etc/cron.monthly
	setFilePerms 0750 /etc/cron.weekly
	
	#setFilePerms 0750 /etc/security  # Removed because it breaks screen unlock via xrdp
	setFilePerms 0755 /etc/security
	setFilePerms 0744 /etc/rc.d/init.d/auditd
	
	setFilePerms 0700 /root
	
	setFilePerms 0600 /etc/cups/client.conf
	setFileOwner 'lp:sys' /etc/cups/client.conf
	setFilePerms 0600 /etc/cups/cupsd.conf
	setFileOwner 'lp:sys' /etc/cups/cupsd.conf
	
	writeToLog " "
}

####################################################

function doModifySSH {
	writeToLog "----------------------------------------------------------"
	writeToLog "9a) Calling - doModifySSH - Set up SSHD Service"
	#modifyVAR ClientAliveInterval  " 900" /etc/ssh/sshd_config
	backupFile /etc/ssh/sshd_config
	
	modifyVAR ClientAliveInterval  "   0" /etc/ssh/sshd_config
	modifyVAR AddressFamily        "   inet"  /etc/ssh/sshd_config
	modifyVAR ClientAliveCountMax  "   3" /etc/ssh/sshd_config
	modifyVAR PermitEmptyPasswords " no" /etc/ssh/sshd_config
	modifyVAR Banner " /etc/issue" /etc/ssh/sshd_config
	modifyVAR PermitUserEnvironment " no" /etc/ssh/sshd_config
	modifyVAR Ciphers " aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,aes192-cbc,aes128-cbc" /etc/ssh/sshd_config
	modifyVAR PermitRootLogin " no" /etc/ssh/sshd_config
	modifyVAR IgnoreRhosts " yes" /etc/ssh/sshd_config
	modifyVAR GatewayPorts " no" /etc/ssh/sshd_config
	modifyVAR PrintLastLog " yes" /etc/ssh/sshd_config
	modifyVAR HostbasedAuthentication " no" /etc/ssh/sshd_config
	modifyVAR MaxAuthTries " 6" /etc/ssh/sshd_config
	writeToLog " "
	RES=(\sbin\service sshd restart)
}

####################################################

function doICMPChanges {
	# make Changes to eliminate ICMP Redirects
	writeToLog "----------------------------------------------------------"
	writeToLog "5) Calling - doICMPChanges - Disable ICMP Redirects"
	backupFile /etc/sysctl.conf
	
	if [ -f "/sbin/sysctl" ]
        then
	        RES=$(sysctl -w net.ipv4.conf.default.send_redirects=0)
		RES=$(sysctl -w net.ipv4.conf.default.accept_redirects=0)
		RES=$(sysctl -w net.ipv4.conf.default.secure_redirects=0)
		
		RES=$(sysctl -w net.ipv4.conf.all.secure_redirects=0)
		RES=$(sysctl -w net.ipv4.conf.all.send_redirects=0)
		RES=$(sysctl -w net.ipv4.conf.all.accept_redirects=0)
		RES=$(sysctl -w net.ipv4.conf.all.log_martians=1)
		RES=$(sysctl -w net.ipv6.conf.default.accept_redirects=0)
        fi
	
   	modifyVAR net.ipv4.conf.all.secure_redirects "= 0" /etc/sysctl.conf
	modifyVAR net.ipv4.conf.default.secure_redirects "= 0" /etc/sysctl.conf
	modifyVAR net.ipv4.conf.default.accept_redirects "= 0" /etc/sysctl.conf
	modifyVAR net.ipv4.conf.default.send_redirects "= 0" /etc/sysctl.conf
	modifyVAR net.ipv4.conf.all.send_redirects "= 0" /etc/sysctl.conf
	modifyVAR net.ipv4.conf.all.accept_redirects "= 0" /etc/sysctl.conf
	modifyVAR net.ipv4.conf.all.log_martians "= 1" /etc/sysctl.conf
	modifyVAR net.ipv6.conf.default.accept_redirects "= 0" /etc/sysctl.conf
	writeToLog " "
}

####################################################

function doDisableInteractiveBoot {
        # 4) Disable Interactive Boot
        #
        backupFile /etc/sysconfig/init

        writeToLog "----------------------------------------------------------"
        writeToLog "4) Calling - doDisableInteractiveBoot - Disable Interactive Boot"
        modifyVAR PROMPT "=no" /etc/sysconfig/init
        writeToLog " "

}

####################################################

function doUmask {
	# 14a) Set umask
	#
	writeToLog "----------------------------------------------------------"
	writeToLog "14a) Calling - doUmask - Set Default UMASK"
	backupFile /etc/login.defs
	backupFile /etc/profile.d/local.sh
	backupFile /etc/profile.d/local.csh
	
	modifyVAR UMASK "     027" /etc/login.defs
	modifyVAR umask " 0027" /etc/profile.d/local.sh
	modifyVAR umask " 0027" /etc/profile.d/local.csh
	# SETTING UMASH IN /ETC/INIT.D/FUNCTION BREAKS THE INAMGE
	# NEEDS A LOT OF TESTING TO IMPLIMENT
	# modifyVAR umask " 027" /etc/init.d/functions
	writeToLog " "

}

####################################################

function doYumFacl {
	
	# Setting umask to 0027 breaks user access to older versions of yum
	# So we set afacl to address this issue
	#
	writeToLog "----------------------------------------------------------"
	writeToLog "14b) Calling - doYumFacl - Set Default FACL on /var/lib/yum to address issue of restrictive umask"
	writeToLog "setfacl -d -m o:rx /var/lib/yum/"
	/usr/bin/setfacl -d -m o:rx /var/lib/yum/
	writeToLog 'find /var/lib/yum/ -type f -exec setfacl -m o:r {} \;'
	/bin/find /var/lib/yum/ -type f -exec /usr/bin/setfacl -m o:r {} \;
	/bin/find /var/lib/yum/ -type d -exec /usr/bin/setfacl -m o:rx {} \;
	/bin/find /var/lib/yum/ -type d -exec /usr/bin/setfacl -d -m o:rx {} \;
	writeToLog " "
	
}

####################################################

function doDisableFingerprint {

## Commented this routine in main on 10 Sept 2013 due to authconfig modifying files in /etc/pam.d
## post configuration

	# Disabling fingerprint using authconfig only for non-desktop builds
	# The desktop builds will have this re-enabled
	writeToLog "----------------------------------------------------------"
	writeToLog "14c) Calling - doDisableFingerprint - Disable fingerprint"
	/usr/sbin/authconfig --disablefingerprint --update 2>&1 | tee -a $LOGFILE
	writeToLog " "

}

####################################################

function doAudit {
#
# 8) Edit /etc/audit/audit.rules:
#
writeToLog "----------------------------------------------------------"
writeToLog "8) Calling - doAudit - Update auditing rules"
backupFile /etc/audit/audit.rules

AUDIT_RULES=/etc/audit/audit.rules
AUDITD_CONF=/etc/audit/auditd.conf
DIA_VERS_BUILD="DIA Base"

rm -rf $CURRENT_DIR/tmp.rules 2>&1 | tee -a $LOGFILE
rm -rf /etc/audit/audit.rules.tmp 2>&1 | tee -a $LOGFILE
rm -rf $CURRENT_DIR/tmp.rules 2>&1 | tee -a $LOGFILE

while read line
do
        if [ "`grep -e \"$line\" /etc/audit/audit.rules`" ]; then
          echo "Audit rule found: $line -- skipping" 2>&1 | tee -a $LOGFILE
        else
          echo "Creating audit.rules list: $line" 2>&1 | tee -a $LOGFILE
          echo $line >> $CURRENT_DIR/tmp.rules
        fi
done < $CURRENT_DIR/AUDIT/rules_to_add

if [ -f $CURRENT_DIR/tmp.rules ]; then

  echo "Appending new audit rules to /etc/audit/audit.rules" 2>&1 | tee -a $LOGFILE

  cat $AUDIT_RULES |grep -v "\-e 2" > /etc/audit/audit.rules.tmp
  mv -f /etc/audit/audit.rules.tmp $AUDIT_RULES 2>&1 | tee -a $LOGFILE

  cat $AUDIT_RULES |grep -v "Make the configuration immutable" > /etc/audit/audit.rules.tmp
  mv -f /etc/audit/audit.rules.tmp $AUDIT_RULES 2>&1 | tee -a $LOGFILE

  echo "# L1.25 Additional rules for $DIA_VERS_BUILD build based on results from SECSCN v6.3" \
  >> $AUDIT_RULES
  cat $CURRENT_DIR/tmp.rules >> $AUDIT_RULES
  echo " " >> $AUDIT_RULES
  echo "# L1.15 Make the configuration immutable - reboot is required to change rules." \
  >> $AUDIT_RULES
  echo "-e 2" >> $AUDIT_RULES

  chmod 400 $AUDIT_RULES 2>&1 | tee -a $LOGFILE
  chown root:root $AUDIT_RULES 2>&1 | tee -a $LOGFILE
fi

writeToLog " "

}

####################################################

function doPostLockdown {

writeToLog " "
writeToLog " "

#---------------------------------------------------
# Multiple audits for services from STIGs and DLB 2.x
# Note: Certain services are not present on the base build but may show up
# later after add-on packages (i.e. ISCSI services)

echo "-- START: Disabling unnecessary services" 2>&1 | tee -a $LOGFILE

$CHKCONFIG xinetd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG avahi-daemon off 2>&1 | tee -a $LOGFILE
$CHKCONFIG bluetooth off 2>&1 | tee -a $LOGFILE
$CHKCONFIG cups off 2>&1 | tee -a $LOGFILE
$CHKCONFIG cups-config-daemon off 2>&1 | tee -a $LOGFILE
$CHKCONFIG irda off 2>&1 | tee -a $LOGFILE
$CHKCONFIG lm_sensors off 2>&1 | tee -a $LOGFILE
$CHKCONFIG portmap off 2>&1 | tee -a $LOGFILE
$CHKCONFIG rpcgssd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG rpcidmapd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG rpcsvcgssd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG sendmail off 2>&1 | tee -a $LOGFILE
$CHKCONFIG setroubleshoot off 2>&1 | tee -a $LOGFILE
$CHKCONFIG yum-updatesd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG atd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG autofs off 2>&1 | tee -a $LOGFILE
$CHKCONFIG firstboot off 2>&1 | tee -a $LOGFILE
$CHKCONFIG hidd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG hplip off 2>&1 | tee -a $LOGFILE
$CHKCONFIG jexec off 2>&1 | tee -a $LOGFILE
$CHKCONFIG mdmonitor off 2>&1 | tee -a $LOGFILE
$CHKCONFIG microcode_ctl off 2>&1 | tee -a $LOGFILE
$CHKCONFIG pcscd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG readahead_early off 2>&1 | tee -a $LOGFILE
$CHKCONFIG readahead_later off 2>&1 | tee -a $LOGFILE
$CHKCONFIG rhnsd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG ypbind off 2>&1 | tee -a $LOGFILE
$CHKCONFIG postfix off 2>&1 | tee -a $LOGFILE
$CHKCONFIG snmpd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG snmptrapd off 2>&1 | tee -a $LOGFILE
$CHKCONFIG iscsi off 2>&1 | tee -a $LOGFILE
$CHKCONFIG iscsid off 2>&1 | tee -a $LOGFILE
$CHKCONFIG NetworkManager off 2>&1 | tee -a $LOGFILE

echo "-- END: Disabling unnecessary services" 2>&1 | tee -a $LOGFILE

writeToLog " "
writeToLog " "

}

####################################################

function doUpdate {

	# Functions that have the ability to update a config should go here; when security script
	# rpm is updated these functions will be run to update portions of the security
	#

	echo " " 2>&1 | tee -a $LOGFILE
	echo "     Starting UPDATE lockdown on `/bin/date`" 2>&1 | tee -a $LOGFILE
	echo " " 2>&1 | tee -a $LOGFILE
	
	writeToLog "----------------------------------------------------------"
	writeToLog "Calling - doUpdate - Run just portions of the security lockdown"
	
	# Stop nails if running
	/sbin/chkconfig nails > /dev/null 2>&1
	if [ $? -eq "0" ]; then
	  /sbin/service nails stop 2>&1 | tee -a $LOGFILE
	fi

	if [ ! -f /etc/.icgc-security.lock ] 
	then
		echo "Cannot apply update...the full lockdown has not yet been applied. Exiting..."
		writeToLog " "
		writeToLog "Cannot apply update...the full lockdown has not yet been applied. Exiting..."
		exit 1
	fi
	
	doPasswdComplexity
	doDisableInteractiveBoot
	doICMPChanges
	doAudit
	doModifySSH
	doUmask
	doYumFacl
	#doDisableFingerprint
        doFilePerms
	doPostLockdown

	# Start nails back up
	/sbin/chkconfig nails > /dev/null 2>&1
	if [ $? -eq "0" ]; then
	  /sbin/service nails start 2>&1 | tee -a $LOGFILE
	fi

	writeToLog " "

	echo " " 2>&1 | tee -a $LOGFILE
	echo "     UPDATE lockdown complete on `/bin/date`" 2>&1 | tee -a $LOGFILE
	echo " " 2>&1 | tee -a $LOGFILE
	
}

####################################################
# Begin main
####################################################
#
# Check command line argument; if none supplied, it will run doUpdate

case ${1} in
  "-v")
	echo " "
	echo -e "\tVersion $AFFIL_VERSION"
	echo " "
	echo " " 
	exit 0
    ;;
  "-h")
        echo " "
	echo "Usage:"
	echo "  No arguments will execute the delta-update security lockdown"
	echo "  <script> -v   Obtain version information"
	echo "  <script> -h   Obtain this help menu"
	echo "  <script> --help   Obtain this help menu"
	echo " " 
	echo " " 
	exit 0
    ;;
  "--help")
	echo " "
	echo "Usage:"
	echo "  No arguments will execute the delta-update security lockdown"
	echo "  <script> -v   Obtain version information"
	echo "  <script> -h   Obtain this help menu"
	echo "  <script> --help   Obtain this help menu"
	echo " " 
	echo " " 
	exit 0
    ;;
  *)
	doUpdate 
	echo "$CURDATE | $OSVERSION | $VERSION | Completed refresh of affiliate security for DIA Base - doUpdate" >> /etc/.icgc-cm.log
	exit 0
    ;;
esac

####################################################
