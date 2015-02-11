#!/bin/csh
#
### Version 1.1 
#
##  Date Created  : 2007-04-17 # 
#                 [P. Whitney DIA]
#
##  CHANGELOG: /etc/profile.d/z_consent.csh
#   - 2011-06-24:  When executing a C shell script, do not prompt for consent
#		   [J. Kulp DIA]


if ($?prompt) then
    /usr/sbin/consent.sh || exit 1
else
    echo ""
endif

