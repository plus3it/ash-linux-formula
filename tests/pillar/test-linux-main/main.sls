# Pillar variables used by ash-linux formula.
#
# Currently, only rsyslog service is targeted for Pillar-usage
#
#################################################################
## ash-linux:
##   lookup:

       # Settings used for configuring syslog service
##     rsyslog:
##       destination: localhost
##       transport: udp
##       log_port: 517
##       match_criteria: *.*
##       disable_locallog: no
##       log_template: RSYSLOG_ForwardFormat

       # Whether to attempt to cac-enable the system
##     cac-enable: false

       # Where to send automated emails
##     notifier-email: notifications@my.fully.qualified.domain

       # STIG-handlers to skip
##     skip-stigs:
##       - RHEL-07-020160
##       - RHEL-07-020161

       # Maximum length of time (in days) to patch system within
##     mustpatch-days: 30

       # Default permission to set on home directories
##     home-mode: 0700

       # Action auditd will take if it overruns its event-queues
##     audit-overflow: <0|1|2>

       # Action auditd will take if log-space is running out
##     audit-space-action: <ignore|syslog|rotate|email|exec|suspend|single|halt>

       # The IP/hostname of a remote node configured to collect
       # event information from the audispd service
##     audisp-server: audispdcol.my.fully-qualified.domain

       # Action to take if audispd detects a disk-full condition
##     audisp-disk-full: <syslog|single|halt>

       # Action to take if audispd is unable to send logs to a
       # remote collector-host
##     audisp-net-fail: <syslog|single|halt>

       # List of accounts that should be banned from deployed systems
##     banned-accts
##       - ftp
##       - games
##       - gopher

       # DNS-related information for SaltStack to enforce if not
       # being received via other means (e.g., DHCP)
##     dns-info
##       nameservers
##         - nameserver1.I.P.addr
##         - nameserver2.I.P.addr
