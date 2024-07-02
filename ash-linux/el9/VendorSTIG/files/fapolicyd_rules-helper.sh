#!/bin/bash
#
set -euo pipefail
#
# Helper-script to handle conditional creation of fapolicyd default-rules so 
# that enabling fapolicyd in "deny-all" mode doesn't break the system
#
################################################################################

DEF_RULE_FILE="/usr/share/fapolicyd/default-ruleset.known-libs"
DEF_RULE_LIST=()
NEW_RULES=0
RULE_DEST_DIR="/etc/fapolicyd/rules.d"
RULE_SORC_DIR="/usr/share/fapolicyd/sample-rules"

# Bomb out if the fapolicyd RPM isn't installed
if [[ $(  rpm -q --quiet fapolicyd )$? -ne 0 ]]
then
  echo "Missing dependency: fapolicyd RPM" >&2
  exit 1
fi

# Read contents of DEF_RULE_FILE into DEF_RULE_LIST array
mapfile -t DEF_RULE_LIST <  "${DEF_RULE_FILE}"

# Create rules as necessary
if [[ ${#DEF_RULE_LIST[*]} -gt 0 ]]
then
  echo "Creating necessary rule-files in ${RULE_DEST_DIR}"

  for RULE_FILE in "${DEF_RULE_LIST[@]}"
  do
    if [[ ! -e ${RULE_DEST_DIR}/${RULE_FILE} ]]
    then
      printf "Creating %s/%s... " "${RULE_DEST_DIR}" "${RULE_FILE}"
      install -bDm 0600 "${RULE_SORC_DIR}/${RULE_FILE}" \
        "${RULE_DEST_DIR}/${RULE_FILE}" || \
          ( echo FAILED ; exit 1 )
      echo SUCCESS
      NEW_RULES=$(( NEW_RULES += 1 ))
    fi
  done
  if [[ ${NEW_RULES} -eq 0 ]]
  then
    echo  # an empty line here so the next line will be the last.
    echo "changed=no comment='No creation of rule-files necessary'"
  else
    echo  # an empty line here so the next line will be the last.
    echo "changed=yes comment='Created ${NEW_RULES} files'"
  fi
fi
