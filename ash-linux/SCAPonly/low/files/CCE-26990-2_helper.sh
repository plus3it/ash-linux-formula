#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID: audit_manual_logon_edits
# - service_irqbalance_enabled
#
# Security identifiers:
# - CCE-26990-2
#
# Rule Summary: Enable IRQ Balance (irqbalance)
#
# Rule Text: The irqbalance service optimizes the balance between power 
#            savings and performance through distribution of hardware 
#            interrupts across multiple processors.  In an environment 
#            with multiple processors (now common), the irqbalance 
#            service provides potential speedups for handling interrupt 
#            requests (helpful in systems with enhanced audit-collection 
#            enabled).
#
#################################################################

cpu_count() {
   local CPUS=`egrep -e "core id" -e ^physical /proc/cpuinfo|xargs -l2 echo| wc -l`
   echo ${CPUS}
}

CPUCOUNT=$(cpu_count)
if [ ${CPUCOUNT} = 1 ]
then
   echo "----------------------------------" >&2
   echo "System is single-core: irqbalance" >&2
   echo "  service will not function" >&2
   echo "----------------------------------" >&2
   RETURN=1
else
   echo "----------------------------------"
   echo "System has multiple (${CPUCOUNT}) CPUs"
   echo "----------------------------------"
   RETURN=0
fi

exit ${RETURN}
