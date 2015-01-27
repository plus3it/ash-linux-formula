#!/bin/sh
#
# Option-parser testing
#
######################################################################
RUNTYPE="${1:-ALL}"
RUNARG="UNDEF"
PROGNAME="${0}"

OPTIONBUFR=`getopt -o ac:v: --long all,category:,vid: -n ${PROGNAME} -- "$@"`

# Ensure option-list is non-null
if [ $? != 0 ]
then
   echo "Terminating..." >&2
   exit 1
fi

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
echo "Run-mode: ${RUNTYPE}"
echo "Run-args: ${RUNARG}"
