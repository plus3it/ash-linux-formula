#!/bin/bash

trap "" 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 \
33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64

function AllowSession()
{
  echo "Welcome to $HOSTNAME! "
  exit 0
}

function EndSession()
{
  SSH_PID=`ps -ef | grep $USER | grep -m 1 'ssh '| awk {'print $2'}`
  echo "Your session is being terminated."
  sleep 1
  kill -s TERM $SSH_PID >& /dev/null
  exit 1
}


## Main Section
##
default=no

# pidoff gdm-binary returns 1 on base server (no X server)
#pidof gdm-binary >& /dev/null

#if [ $? -eq 1 ]
#then
#	exit 0
#fi

cat /etc/issue
echo ""
while [ true ]
do
	echo -n "Do you agree to these terms (yes/no)? [no] "
	read ans


	# If no answer was given AND if the read was successful, then treat
	# the user's response as accepting the default.
	#
	# Note when the user enters a ctrl-D, the read will fail; hence the
	# status will be a 1.  In such case, the user's response will be
	# treated as if they had entered "no".
	#
	if [ "$ans" == "" -a $? -eq 0 ]
	then
		ans=$default
	fi
	

	case "$ans" in
		"yes")	AllowSession;;
		"no")	EndSession;;
		"")	EndSession;;
		*)	echo "Error:  A 'yes' or a 'no' response is required!";;
	esac
done

exit 0
