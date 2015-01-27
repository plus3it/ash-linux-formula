#!/bin/sh
#
# Option-parser testing
#
######################################################################
RUNTYPE="ALL"
RUNARG="UNDEF"
PROGNAME="${0}"
DEBUGLVL="warning"
SALTROOT="/srv/salt"
SALTCMD="/usr/bin/salt-call --no-color --local -l ${DEBUGLVL} state.sls"
INSTALLED="false"
DATETAG=`date "+%Y%m%d_%H%M%S"`
LOGFILE="/var/tmp/salt_run-${DATETAG}.log"

# Make sure Saltstack RPM is present
rpm --quiet -qf /usr/bin/salt-call && INSTALLED="true"
if [ "${INSTALLED}" = "false" ]
then
   echo "Saltstack RPMs not installed. Aborting!"
   exit 1
fi

OPTIONBUFR=`getopt -o ac:v:h: --long all,category:,vid:,salt-root:: -n ${PROGNAME} -- "$@"`

# Ensure parsable option-list is non-null
if [ $? != 0 ]
then
   echo "Terminating..." >&2
   exit 1
fi

VidListConstruct(){
   printf "Constructing V-ID list... "
   if [ "${1}" = "" ]
   then
      VIDLIST=`find -L ${VIDHOME} -type f -name "V*.sls" | sort | sed '{
         s/^.*STIGbyID/STIGbyID/
         s/\.sls$//
      }'`
   else
      for VID in ${1}
      do
         VIDLIST="${VIDLIST} `find -L ${VIDHOME} -type f -name "${VID}.sls" | \
	 sort | sed '{
	    s/^.*STIGbyID/STIGbyID/
	    s/\.sls$//
         }' ; echo`"
      done
   fi
   echo "Done!"
   echo "Starting test-run: will log to ${LOGFILE}"

   # Run Test(s)
   for TESTID in ${VIDLIST}
   do
      ${SALTCMD} ${TESTID} 2>&1
   done | tee ${LOGFILE}
}

RunLayer(){
   SERCHTYP="${1}"
   SERCHLST="${2}"
   VIDHOME="${SALTROOT}/${3:-STIGbyID}"

   case ${SERCHTYP} in
      ALL)
         VidListConstruct
         ;;
      CATEGORY)
         case ${SERCHLST} in
	    1|cat1|Cat1)
               VIDHOME="${SALTROOT}/STIGbyID/cat1"
	       ;;
	    2|cat2|Cat2)
               VIDHOME="${SALTROOT}/STIGbyID/cat2"
	       ;;
	    3|cat3|Cat3)
               VIDHOME="${SALTROOT}/STIGbyID/cat3"
	       ;;
         esac
         VidListConstruct
         ;;
      VID)
         VidListConstruct "${SERCHLST}"
         ;;
   esac
## # Locate all the VID SLS files and create a list
## printf "Constructing V-ID list... "
## VIDLIST=`find -L ${3} -type f -name "V*.sls" | sort | sed '{
## s/^.*STIGbyID/STIGbyID/
## s/\.sls$//
## }'`
## echo "Done!"
}

# Note the quotes around '$OPTIONBUFR': they are essential!
eval set -- "$OPTIONBUFR"

while true ; do
   case "$1" in
      -a|--all)
         echo "The 'all-run' option has been selected".
         RUNTYPE="ALL"
         RUNARG="ALL"
         shift
         break
         ;;
      -c|--category)
         echo "Full-category run-mode selected: will run category '${2}'"
         RUNTYPE="CATEGORY"
         RUNARG="${2}"
         VIDHOME="${VIDHOME}/${2}"
         shift 2
         break
         ;;
      -v|--vid) 
         # v has an mandatory argument. As we are in quoted mode,
         # an empty parameter will be generated if its optional
         # argument is not found.
         case "$2" in
            "")
               echo "Error: option required but not specified"
               shift 2
               ;;
            *)
               echo "Discrete VID-mode selected; will run VID '${2}'"
               RUNTYPE="VID"
               if [ "${RUNARG}" = "UNDEF" ]
               then
                  RUNARG="${2}"
               else
                  RUNARG="${RUNARG} ${2}"
               fi
               shift 2
               ;;
         esac
         ;;
      -h|--salt-root)
         VIDHOME="${2}"
         shift 2
         ;;
      --)
         shift
         break
         ;;
      *)
         echo "Internal error!"
         exit 1
         ;;
   esac
done

RunLayer "${RUNTYPE}" "${RUNARG}" "${VIDHOME}"
