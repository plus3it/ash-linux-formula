#!/bin/bash

####################################################
AFFIL_VERSION="2011.3-12.dia.v1.0"
PATH=$PATH:/sbin:/usr/sbin:/bin:/sbin
export PATH
CURRENT_DIR=`/usr/bin/dirname $0`
CURDATE=`date +%Y%m%d-%H%M%S`
LOGFILE=$CURRENT_DIR/install_log.$CURDATE
INDENT="                             "
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

function doDisableIPV6 {
	# 6) Disable ipv6
	#
	# /etc/sysctl.conf is backed up in doICMPChanges
	#
	writeToLog "----------------------------------------------------------"
	writeToLog "6) Calling - doDisableIPV6 - Disable IPV6"
	backupFile /etc/hosts
	
	RES=$(sysctl -w net.ipv6.conf.all.disable_ipv6=1)
	modifyVAR net.ipv6.conf.all.disable_ipv6 "= 1" /etc/sysctl.conf
	# delete the IPV6 loop back interface entry in /etc/hosts
	deleteLine "^\:\:1"  /etc/hosts
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
	# Note: local.sh and local.csh are backed up in the routine doInactiveTerm
	backupFile /etc/login.defs
	
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

function doAudit {
#
# 8) Edit /etc/audit/audit.rules:
#
writeToLog "----------------------------------------------------------"
writeToLog "8) Calling - doAudit - Install auditing rules"

AUDIT_RULES=/etc/audit/audit.rules
AUDITD_CONF=/etc/audit/auditd.conf

# The rules are simply the parameters that would be passed to auditctl.
backupFile /etc/audit/audit.rules
backupFile /etc/audit/auditd.conf

/bin/cat <<EOL > $AUDIT_RULES
# First rule - delete all
-D

# Increase the buffers to survive stress events.
# Make this bigger for busy systems
-b 16394

# Feel free to add below this line. See auditctl man page

#  L1.16 Set failure mode to panic
# Default: 2
-f 2

## Get rid of all anonymous and daemon junk.  It clogs up the logs and doesn't
# do anyone # any good.
-a exit,never -F auid>2147483645
-a exit,never -F auid!=0 -F auid<500

##########
# This section contains system calls that will be audited
##########

## Things that could affect time
-a always,exit -F arch=b64 -S adjtimex -S clock_settime -S settimeofday -k SYS_time-change
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

## Things that could affect system locale
-a exit,always -F arch=b64 -S sethostname -k SYS_system-locale

## unsuccessful creation
-a exit,always -F arch=b64 -S creat -S mkdir -S mknod -S link -S symlink -F exit=-EACCES -k SYS_creation
-a exit,always -F arch=b64 -S mkdirat -S mknodat -S linkat -S symlinkat -F exit=-EACCES -k SYS_creation

## unsuccessful open - open and openat may be combined on support arches
-a exit,always -F arch=b64 -S openat -F exit=-EACCES -k SYS_open
-a exit,always -F arch=b64 -S open -F exit=-EACCES -k SYS_open
-a exit,always -F arch=b64 -S openat -F exit=-EPERM -k SYS_open
-a exit,always -F arch=b64 -S open -F exit=-EPERM -k SYS_open

## unsuccessful close
-a exit,always -F arch=b64 -S close -F exit=-EACCES -k SYS_close

## unsuccessful modifications - renameat may be combined on supported arches
-a exit,always -F arch=b64 -S rename -S truncate -S ftruncate -F exit=-EACCES -k SYS_mods
-a exit,always -F arch=b64 -S renameat -F exit=-EACCES -k SYS_mods
-a exit,always -F perm=a -F exit=-EACCES -k SYS_mods
-a exit,always -F perm=a -F exit=-EPERM -k SYS_mods

## unsuccessful deletion - unlinkat may be combined on supported arches
-a exit,always -F arch=b64 -S rmdir -S unlink -F exit=-EACCES -k SYS_delete
-a exit,always -F arch=b64 -S unlinkat -F exit=-EACCES -k SYS_delete

# Mount options.
-a exit,always -F arch=b64 -S mount -S umount2 -k SYS_mount

# Permissions auditing

-a exit,always -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -k SYS_perm_mod
-a exit,always -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -k SYS_perm_mod
-a exit,always -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -k perm_mod

# audit umask changes.
# This is uselessly noisy.
# -a entry,always -S umask -k umask

# Audit *everything* useful someone does when su'ing to root
# Had to add an entry for getting rid of anonymous records.  They are only
# moderately useful but have *way* too much noise since this covers things like
# cron as well.

# The following rule is more complete but uselessly noisy.

#-a exit,always -F arch=b64 -F auid!=0 -F uid=0 -S write -S capset -S chown -S chroot -S creat -S execve -S fork -S vfork -S link -S mkdir -S mknod -S pivot_root -S quotactl -S reboot -S rmdir -S setdomainname -S sethostname -S setsid -S settimeofday -S setuid  -S swapoff -S swapon -S symlink -k su-root-activity

-a exit,always -F arch=b64 -F auid!=0 -F uid=0 -S capset -S mknod -S pivot_root -S quotactl -S setdomainname -S sethostname -S setsid -S settimeofday -S setuid -S swapoff -S swapon -k su-root-activity

# Nobody should be reading from here, or writing to here.
# Ideally, this file won't even exist.
-w /proc/kcore -p rw -k kcore
-a exit,always -F arch=b64 -S ptrace -k SYS_paranoid
-a exit,always -F arch=b64 -S personality -k SYS_paranoid

# Networking
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale

##########
# This section contains watching security policy relevant files that will be audited
#
# NOTE: The following should not create any log entries unless "there is a problem" (in other words: write or append to policy files)
##########

# Access control - local control files
-w /etc/group -p wa -k LOCAL_auth
-w /etc/group- -p wa -k LOCAL_auth
-w /etc/passwd -p wa -k LOCAL_auth
-w /etc/passwd- -p wa -k LOCAL_auth
-w /etc/gshadow -p wa -k LOCAL_auth
-w /etc/shadow -p wa -k LOCAL_auth
-w /etc/shadow- -p wa -k LOCAL_auth

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Local login
-w /etc/login.defs -p wa -k CFG_sys
-w /etc/securetty -p wa -k CFG_sys

-w /etc/shells -p wa -k CFG_shell
-w /etc/profile -p wa -k CFG_shell
-w /etc/bashrc -p wa -k CFG_shell
-w /etc/csh.cshrc -p wa -k CFG_shell
-w /etc/csh.login -p wa -k CFG_shell

# Generally good things to audit.
-w /var/spool/at -p wa -k CFG_sys
-w /etc/at.deny -p wa -k CFG_sys

# "Cron" related
-w /etc/cron.deny -p wa -k CFG_cron
-w /etc/cron.d -p wa -k CFG_cron
-w /etc/cron.daily -p wa -k CFG_cron
-w /etc/cron.hourly -p wa -k CFG_cron
-w /etc/cron.monthly -p wa -k CFG_cron
-w /etc/cron.weekly -p wa -k CFG_cron
-w /etc/crontab -p wa -k CFG_cron
-w /etc/anacrontab -p wa -k CFG_cron

-w /var/log/faillog -p wa -k faillog
-w /var/log/lastlog -p wa -k lastlog
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

# Sudo related
-w /etc/sudoers -p wa -k CFG_sudoers

# System startup/boot-related files
-w /etc/grub.conf -p wa -k CFG_boot
-w /etc/sysconfig -p wa -k CFG_boot
-w /etc/inittab -p wa -k CFG_boot
-w /etc/rc.d/init.d -p wa -k CFG_boot
-w /etc/rc.local -p wa -k CFG_boot
-w /etc/rc.sysinit -p wa -k CFG_boot
-w /etc/xinetd.d -p wa -k CFG_boot

# System service configuration files
-w /etc/services -p wa -k CFG_sys
-w /etc/sysctl.conf -p wa -k CFG_sys
-w /etc/modprobe.conf -p wa -k CFG_sys
-w /etc/modprobe.conf.d -p wa -k CFG_sys

# Watch configuration files in /etc/security
-w /etc/security/access.conf -p wa -k CFG_security
-w /etc/security/chroot.conf -p wa -k CFG_security
-w /etc/security/console.perms -p wa -k CFG_security
-w /etc/security/group.conf -p wa -k CFG_security
-w /etc/security/limits.conf -p wa -k CFG_security
-w /etc/security/pam_env.conf -p wa -k CFG_security
-w /etc/security/time.conf -p wa -k CFG_security

# Watch xinetd related files
-w /etc/xinted.conf -p wa -k CFG_xinted
-w /etc/xinetd.d/chargen-dgram -p wa -k CFG_xinted.d
-w /etc/xinetd.d/chargen-stream -p wa -k CFG_xinted.d
-w /etc/xinetd.d/daytime-dgram -p wa -k CFG_xinted.d
-w /etc/xinetd.d/daytime-stream -p wa -k CFG_xinted.d
-w /etc/xinetd.d/echo-dgram -p wa -k CFG_xinted.d
-w /etc/xinetd.d/echo-stream -p wa -k CFG_xinted.d
-w /etc/xinetd.d/rsync -p wa -k CFG_xinted.d
-w /etc/xinetd.d/time-dgram -p wa -k CFG_xinted.d
-w /etc/xinetd.d/time-stream -p wa -k CFG_xinted.d

# Watch for changes to NTP files
-w /etc/ntp.conf -p wa -k CFG_ntp
-w /etc/ntp/keys -p wa -k CFG_ntp

# Watch for changes to remote access related files
-w /etc/hosts.allow -p wa -k CFG_remote
-w /etc/hosts.deny -p wa -k CFG_remote
-w /etc/issue -p wa -k CFG_remote
-w /etc/issue.net -p wa -k CFG_remote
-w /etc/resolv.conf -p wa -k CFG_remote
-w /etc/host.conf -p wa -k CFG_remote
# not found -w /etc/snmp/snmpd.conf -p wa -k CFG_remote

# watch for changes to SSH related files
-w /etc/ssh/sshd_config -p wa -k CFG_ssh
-w /etc/ssh/ssh_config -p wa -k CFG_ssh
-w /etc/ssh/ssh_host_dsa_key -p wa -k CFG_ssh_key
-w /etc/ssh/ssh_host_dsa_key.pub -p wa -k CFG_ssh_key
-w /etc/ssh/ssh_host_key -p wa -k CFG_ssh_key
-w /etc/ssh/ssh_host_key.pub -p wa -k CFG_ssh_key
-w /etc/ssh/ssh_host_rsa_key -p wa -k CFG_ssh_key
-w /etc/ssh/ssh_host_rsa_key.pub -p wa -k CFG_ssh_key
-w /etc/ssh/auth_keys -p wa -k CFG_ssh_key
-w /etc/ssh/local_key -p wa -k CFG_ssh_key
-w /etc/ssh/moduli -p wa -k CFG_ssh_key

# Watch miscellaneous system files
-w /etc/aliases -p wa -k CFG_sys
-w /etc/krb5.conf -p wa -k CFG_sys
-w /etc/initlog.conf -p wa -k CFG_sys
# Error sending add rule data request (No such file or directory)
# -w /etc/firmware/microcode.dat -p wa -k CFG_sys

# Watch file system configuration files
-w /etc/fstab -p wa -k CFG_file_sys
-w /etc/exports -p wa -k CFG_file_sys
-w /etc/default -p wa -k CFG_file_sys

# Watch network related files
-w /etc/hosts -p wa -k CFG_net_sys
-w /etc/nsswitch.conf -p wa -k CFG_net_sys
-w /etc/default/nss -p wa -k CFG_net_sys
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Watch MAC
-w /etc/selinux/ -p wa -k MAC-policy

# Watch audit related files
-w /etc/rc.d/init.d/auditd -p wa -k CFG_audit
-w /etc/audit/auditd.conf -p wa -k CFG_audit
-w /etc/rsyslog.conf -p wa -k CFG-audit
-w /etc/rsyslog.d/remote.conf -p wa -k CFG_audit
-w /etc/logrotate.conf -p wa -k CFG_audit
-w /etc/logrotate.d/ -p wa -k CFG_audit

# Watch ldap related files
-w /etc/ldap.conf -p wa -k CFG_etc_ldap
-w /etc/ld.so.conf -p wa -k CFG_etc_ldap
-w /etc/ld.so.conf.d -p wa -k CFG_etc_ldap

# PAM related
-w /etc/pam.d -p wa -k CFG_pam
-w /etc/pam_smb.conf -p wa -k CFG_pam

# Watch for changes to system PKI files
-w /etc/pki/private -p wa -k PKI
-w /etc/pki/public -p wa -k PKI
-w /etc/pki/cacerts -p wa -k PKI
# Error sending add rule data request (No such file or directory)
# -w /etc/pki/private/$HOSTNAME.pem -p wa -k PKI
# -w /etc/pki/public/$HOSTNAME.pub -p wa -k PKI

##########
# This section contains auditing the execution of commands
#
##########

-w /bin/vi -p wx -k EXEC_command
-w /sbin/shutdown -p wx -k EXEC_command
-w /sbin/reboot -p wx -k EXEC_command
-w /sbin/halt -p wx -k EXEC_command
-w /sbin/service -p wx -k EXEC_command
-w /bin/rm -p wx -k EXEC_command

#########
# OTHER RULES from SECSCN
#
#########
# L1.22 Ensure the system is configured to record process and session information.
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

-w /etc/sudoers -p wa -k actions

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

#########
# L1.25 Ensure the system is configured to record execution of privileged commands.
-a always,exit -F path=/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/netreport -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/ping -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

# SRG-OS-000064 V-38580 - loading and unloading dynamic kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

#########
# L1.15 Make the configuration immutable - reboot is required to change rules.
-e 2

EOL

echo "--L1.2 audit daemon runs at all run levels 1-5." 2>&1 | tee -a $LOGFILE
# L1.2 Verify audit daemon runs at all run levels 1-5.
if [ -f "/sbin/chkconfig" ]
then
	RES=$(/sbin/chkconfig --level 12345 auditd on)
fi

echo "--L1.8, L1.9, L1.10, L1.11, L1.12 $AUDITD_CONF " 2>&1 | tee -a $LOGFILE
modifyVAR disk_full_action " = HALT"  $AUDITD_CONF
modifyVAR disk_error_action " = HALT"  $AUDITD_CONF
modifyVAR flush " = SYNC"  $AUDITD_CONF
modifyVAR space_left_action " = email"  $AUDITD_CONF
modifyVAR admin_space_left_action " = email"  $AUDITD_CONF

echo "--L1.13 Check that administrators are notified on disk full." 2>&1 | tee -a $LOGFILE
echo "    edit $AUDITD_CONF" 2>&1 | tee -a $LOGFILE
echo "    action_mail_acct = <Valid administrator email address or alias>" 2>&1 | tee -a $LOGFILE

writeToLog " "

# Done with base audit rules
}

####################################################
# 
# 1) Disable Empty Passwords in PAM
#
# Note: These files have already been backed up in the routine doPasswdComplexity 
#
function doDisableEmpty {

  writeToLog "----------------------------------------------------------"
  writeToLog "2) Calling - doDisableEmpty - Disable Empty Passwords in PAM"
  removeTextFromLine 'nullok' 'auth*[ ]*sufficient*[ ]*pam_unix.so' /etc/pam.d/system-auth
  removeTextFromLine 'nullok' 'auth*[ ]*sufficient*[ ]*pam_unix.so' /etc/pam.d/system-auth-ac
  removeTextFromLine 'nullok' 'auth*[ ]*sufficient*[ ]*pam_unix.so' /etc/pam.d/password-auth
  removeTextFromLine 'nullok' 'auth*[ ]*sufficient*[ ]*pam_unix.so' /etc/pam.d/password-auth-ac
  removeTextFromLine 'nullok' 'password*[ ]*sufficient*[ ]*pam_unix.so' /etc/pam.d/system-auth
  removeTextFromLine 'nullok' 'password*[ ]*sufficient*[ ]*pam_unix.so' /etc/pam.d/system-auth-ac
  removeTextFromLine 'nullok' 'password*[ ]*sufficient*[ ]*pam_unix.so' /etc/pam.d/password-auth
  removeTextFromLine 'nullok' 'password*[ ]*sufficient*[ ]*pam_unix.so' /etc/pam.d/password-auth-ac
  writeToLog " "

}

####################################################
#
# 3) Rule ID: deny_Login_attempts
#
# Note: These files have already been backed up in the routine doPasswdComplexity 
#

function doConfigLoginAttempts {

  writeToLog "----------------------------------------------------------"
  writeToLog "3) Calling - doConfigLoginAttempts - Set Login attempts"
  # REL 6.x
  # insert lines in /etc/pam.d/password-auth-ac
  insertLine "auth*[ ]*sufficient*[ ]*pam_unix.so" "auth        required       pam_tally2.so file=/var/log/tallylog onerr=fail deny=3 quiet unlock_time=900" /etc/pam.d/password-auth-ac
  insertLine "account*[ ]*required*[ ]*pam_unix.so" "account        required       pam_tally2.so" /etc/pam.d/password-auth-ac

  # REL 5.x
  # insert lins in /etc/pam.d/system-auth  (cause password references system-auth)
  insertLine "auth*[ ]*sufficient*[ ]*pam_unix.so" "auth        required       pam_tally2.so file=/var/log/tallylog onerr=fail deny=3 quiet unlock_time=900" /etc/pam.d/system-auth
  insertLine "account*[ ]*required*[ ]*pam_unix.so" "account        required       pam_tally2.so" /etc/pam.d/system-auth

  writeToLog " "

  #
  # Done with Account/password locking
}

####################################################
#
# 7) Add auditing at boot
#

function doEnableAuditBoot {

  writeToLog "----------------------------------------------------------"
  writeToLog "7) Calling - doEnableAuditBoot - Enable Auditing on boot"
  backupFile /boot/grub/grub.conf
  
  appendToLine "^\s*kernel" " audit=1" /boot/grub/grub.conf
  writeToLog " "

  #
  # Done
}

####################################################
#
# 9a) Set Terminal inactivity time out for the Shells
# 
# Note: the "readonly TMOUT" line was commented by DIA
# as this was not necessary, nor was it mandated by any security scan
#

function doInactiveTerm {

  writeToLog "----------------------------------------------------------"
  writeToLog "9b) Calling - doInactiveTerm - Set terminal inactivity Timeout"
  backupFile /etc/profile.d/local.sh
  backupFile /etc/profile.d/local.csh

  if [ ! -f /etc/profile.d/local.sh ]
  then
	touch /etc/profile.d/local.sh
  fi
	TEST=$(grep TMOUT=900 /etc/profile.d/local.sh)
	if [ -z "$TEST" ]
	then

/bin/cat <<EOL >> /etc/profile.d/local.sh
export TMOUT=900
#readonly TMOUT
EOL
	fi
	TEST=$(grep "if tty -s" /etc/profile.d/local.sh)
	if [ -z "$TEST" ]
	then

/bin/cat <<EOL >> /etc/profile.d/local.sh
if tty -s; then
  mesg n
fi
EOL
	fi

  if [ ! -f /etc/profile.d/local.csh ]
  then
        touch /etc/profile.d/local.csh
  fi
	TEST=$(grep autologout=15 /etc/profile.d/local.csh)
	if [ -z "$TEST" ]
	then
/bin/cat <<EOL >> /etc/profile.d/local.csh
set autologout=15
tty -s
if ( \$? == 0 ) mesg n
EOL
	fi

  writeToLog " "
  
}

####################################################
#
# 10) limit password reuse (last 24 passwords)
#  sed -i '/password*[ ]*sufficient*[ ]*pam_unix.so/I s/$/ remember=24/' /etc/pam.d/password-auth-ac
#
# Note: These files are backed up in doPasswdComplexity 

function doPasswdConfig {

  writeToLog "----------------------------------------------------------"
  writeToLog "10) Calling - doPasswdConfig - Setup password reuse rules"
  appendToLine "password*[ ]*sufficient*[ ]*pam_unix.so"  " remember=24" /etc/pam.d/password-auth-ac
  appendToLine "password*[ ]*sufficient*[ ]*pam_unix.so"  " remember=24" /etc/pam.d/password-auth
  appendToLine "password*[ ]*sufficient*[ ]*pam_unix.so"  " remember=24" /etc/pam.d/system-auth-ac
  appendToLine "password*[ ]*sufficient*[ ]*pam_unix.so"  " remember=24" /etc/pam.d/system-auth
  writeToLog " "
  #
  # Done with umask

}

####################################################
#
# 11) Disable Cores
#

function doDisableCore {

  writeToLog "----------------------------------------------------------"
  writeToLog "11) Calling - doDisableCore - Disable CORE files"
  backupFile /etc/security/limits.conf
  
  modifyLine "hard*[ ]*core" "*     hard   core    0" /etc/security/limits.conf

  #echo "#11 = $?"
  if [ $? == 3 ];then
        # error 3 means pattern was not found so we insert the line
        insertLine "End of file" "*     hard   core    0" /etc/security/limits.conf
  fi
  writeToLog " "

  #
  # Done with umask
}

####################################################
#
# 12) inactive user gets 30 days by default
#
function doInactiveUserPrefs {

  writeToLog "----------------------------------------------------------"
  writeToLog "12) Calling - doInactiveUserPrefs - Set inactive user account Lock"
  backupFile /etc/default/useradd

  modifyVAR INACTIVE "=30" /etc/default/useradd
  writeToLog " "
  #
  # Done with useradd
  
}

####################################################
#
# 13) Fix /etc/fstab
# Add nosuid and nodev to: /home, /boot, /tmp, /usr, /var
#
# ext4 defaults = rw,suid,dev,exec,auto,nouser,async
#
# setting nodev on var breaks mock. We need to address this at some point
# we need some logic to parse settins a user may have changed 
#
function doConfigFstab {

  writeToLog "----------------------------------------------------------"
  writeToLog "13) Calling - doConfigFstab - Set Filesystem mount options and remount"
  backupFile /etc/fstab
  
  sed -i '/home*[ ]*ext/ s/defaults/rw,nosuid,nodev,exec,auto,nouser,async/g' /etc/fstab
  sed -i '/tmp*[ ]*ext/ s/defaults/rw,nosuid,nodev,exec,auto,nouser,async/g' /etc/fstab
  sed -i '/boot*[ ]*ext/ s/defaults/rw,nosuid,nodev,exec,auto,nouser,async/g' /etc/fstab
  sed -i '/var*[ ]*ext/ s/defaults/rw,nosuid,nodev,exec,auto,nouser,async/g' /etc/fstab
  
  # NOSUID BREAKS SUDO SO WE CANT DO IT on /usr
  sed -i '/usr*[ ]*ext/ s/defaults/rw,nodev,exec,auto,nouser,async/g' /etc/fstab
  
  mount -o remount /usr > /dev/null 2>&1
  mount -o remount /home > /dev/null 2>&1
  mount -o remount /tmp > /dev/null 2>&1
  mount -o remount /boot > /dev/null 2>&1
  mount -o remount /var > /dev/null 2>&1
  
  writeToLog " "
}

####################################################

function doMainFunctions {

	echo " " 2>&1 | tee -a $LOGFILE
	echo "     Starting MAIN lockdown on `/bin/date`" 2>&1 | tee -a $LOGFILE
	echo " " 2>&1 | tee -a $LOGFILE

	writeToLog "----------------------------------------------------------"
	writeToLog "Calling - doMainFunctions - Invoking MAIN lockdown routine"

	echo "Starting update-only in security lockdown script."
	echo "See log file at /opt/updates/security-layer-core/install_log(date)"
		
	if [ -f /etc/.icgc-security.lock ] 
	then
		echo "The full lockdown has already been applied. Exiting..."
		writeToLog " "
		writeToLog "The full lockdown has already been applied. Exiting..."
		exit 1
	fi
	doPasswdComplexity
	doDisableEmpty 
	doConfigLoginAttempts 
	doDisableInteractiveBoot
	doICMPChanges
	# doDisableIPV6
	doEnableAuditBoot
	doAudit
	doModifySSH
	doInactiveTerm
	doPasswdConfig
	doDisableCore
	doInactiveUserPrefs
	doConfigFstab
	doUmask
	doYumFacl
	doFilePerms
	
	#     Set onetime run lock file
	touch /etc/.icgc-security.lock
	
	writeToLog " "

	echo " " 2>&1 | tee -a $LOGFILE
	echo "     MAIN lockdown complete on `/bin/date`" 2>&1 | tee -a $LOGFILE
	echo " " 2>&1 | tee -a $LOGFILE

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
	#doDisableIPV6
	doAudit
	doModifySSH
	doUmask
	doYumFacl
        doFilePerms
	writeToLog " "

	echo " " 2>&1 | tee -a $LOGFILE
	echo "     UPDATE lockdown complete on `/bin/date`" 2>&1 | tee -a $LOGFILE
	echo " " 2>&1 | tee -a $LOGFILE
	
}




####################################################
# Begin main
####################################################
#
# Check command line argument; if "update" is supplied and the lock file exists, it will only run doUpdate:   
# Otherwise, the standard procedure is to execute this script without command line arguments which
# will invoke doMainFunctions

case ${1} in
  "-update")
        doUpdate 
	echo "$CURDATE | $OSVERSION | $VERSION | Completed Affiliate core security layer - doUpdate" >> /etc/.icgc-cm.log
	exit 0
    ;;
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
	echo "  No arguments will execute the complete security lockdown"
	echo "  <script> -v   Obtain version information"
	echo "  <script> -h   Obtain this help menu"
	echo "  <script> --help   Obtain this help menu"
	echo "  <script> -update   Apply a subset of the lockdown process (only possible if full lockdown has already been executed)"
	echo " " 
	echo " " 
	exit 0
    ;;
  "--help")
	echo " "
	echo "Usage:"
	echo "No arguments will execute the complete security lockdown"
	echo "<script> -v   Obtain version information"
	echo "<script> -h   Obtain this help menu"
	echo "<script> --help   Obtain this help menu"
	echo "<script> -update   Apply a subset of the lockdown process (only possible if full lockdown has already been executed)"
	echo " " 
	echo " " 
	exit 0
    ;;
  *)
	doMainFunctions 
	echo "$CURDATE | $OSVERSION | $VERSION | Completed Affiliate core security layer - doMainFunctions" >> /etc/.icgc-cm.log
	exit 0
    ;;
esac

####################################################
