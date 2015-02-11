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

script_V38666-describe:
  cmd.script:
    - source: salt://STIGbyID/cat1/files/V38666.sh
    - cwd: /root

# Will need to update with correct package-name
{% set MSFEpkg = 'MSFElinux' %}
{% set NAIdir = '/opt/NAI/LinuxShield/engine/dat' %}

# If MSFE is installed, check the 'freshness' of its scan dbs and history
{% if salt['pkg.version'](MSFEpkg) %}

# The following is an ugly hack. Need to replace the following checks 
# with SaltStatck's "file.lstat" module. Can pull the 'st_mtime' 
# attribute then compare to system's current time in seconds
# (e.g., `date '+%s'`) 

cmd_V38666-scanChck:
  cmd.run:
    - name: 'find {{ NAIdir }} -type f -mtime -7 -name avvscan.dat > /tmp/age ; test -s /tmp/age'

cmd_V38666-namesChck:
  cmd.run:
    - name: 'find {{ NAIdir }} -type f -mtime -7 -name avvnames.dat > /tmp/age ; test -s /tmp/age'

cmd_V38666-cleanChck:
  cmd.run:
    - name: 'find {{ NAIdir }} -type f -mtime -7 -name avvclean.dat > /tmp/age ; test -s /tmp/age'

# If not installed, see if it's available in the Yum repos
{% else %}
pkg_V38666:
  pkg.installed:
    - name: '{{ MSFEpkg }}'

  {% if salt['pkg.version'](MSFEpkg) %}
notify_V38666-instStat:
  cmd.run:
    - name: 'echo "Installed HBSS package"'
  {% else %}
notify_V38666-instStat:
  cmd.run:
    - name: 'printf "** WARNING **\n  Could neither find installed HBSS\n  package nor install one.\n"'
  {% endif %}
{% endif %}
