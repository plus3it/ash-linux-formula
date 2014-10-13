#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38666
# Finding ID:	V-38666
# Version:	RHEL-06-000284
# Finding Level:	High
#
#     The system must use and update a DoD-approved virus scan program. 
#     Virus scanning software can be used to detect if a system has been 
#     compromised by computer viruses, as well as to limit their spread to 
#     other systems.
#
############################################################

# Will need to update with correct package-name
pkg_V38666:
  pkg.installed:
  - name: MSFElinux

##################################################################
# FILE AGE TEST
#   curtime=`(date "+%s")` filetime=`stat -c "%Y" ${FILENAME}` \
#   diff=$(( (curtime - filetime) / 86400 )) ; test $diff -le 7
# <Better method but longer than leveraging `find`>
##################################################################

cmd_V38666-scanChck:
  cmd.run:
  - name: 'find /opt/NAI/LinuxShield/engine/dat -type f -mtime -7 -name avvscan.dat > /tmp/age ; test -s /tmp/age'
  - onlyif: pkg_V38666

cmd_V38666-namesChck:
  cmd.run:
  - name: 'find /opt/NAI/LinuxShield/engine/dat -type f -mtime -7 -name avvnames.dat > /tmp/age ; test -s /tmp/age'
  - onlyif: pkg_V38666

cmd_V38666-cleanChck:
  cmd.run:
  - name: 'find /opt/NAI/LinuxShield/engine/dat -type f -mtime -7 -name avvclean.dat > /tmp/age ; test -s /tmp/age'
  - onlyif: pkg_V38666
