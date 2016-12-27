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

{%- set stig_id = '38666' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}
# Will need to update with correct package-name
{%- set MSFEpkg = 'MSFElinux' %}
{%- set NAIdir = '/opt/NAI/LinuxShield/engine/dat' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ sls.split('.')[:-1] | join('/') }}/files/V{{ stig_id }}.sh
    - cwd: /root

{%- if salt.pkg.version(MSFEpkg) %}

# If MSFE is installed, check the 'freshness' of its scan dbs and history

# The following is an ugly hack. Need to replace the following checks 
# with SaltStatck's "file.lstat" module. Can pull the 'st_mtime' 
# attribute then compare to system's current time in seconds
# (e.g., `date '+%s'`) 

cmd_V{{ stig_id }}-scanChck:
  cmd.run:
    - name: 'find {{ NAIdir }} -type f -mtime -7 -name avvscan.dat > /tmp/age ; test -s /tmp/age'

cmd_V{{ stig_id }}-namesChck:
  cmd.run:
    - name: 'find {{ NAIdir }} -type f -mtime -7 -name avvnames.dat > /tmp/age ; test -s /tmp/age'

cmd_V{{ stig_id }}-cleanChck:
  cmd.run:
    - name: 'find {{ NAIdir }} -type f -mtime -7 -name avvclean.dat > /tmp/age ; test -s /tmp/age'

{%- else %}

    {%- if salt.pkg.latest_version(MSFEpkg) %}

# If not installed, see if it's available in the Yum repos
pkg_V{{ stig_id }}:
  pkg.installed:
    - name: '{{ MSFEpkg }}'

notify_V{{ stig_id }}-installed:
  cmd.run:
    - name: 'echo "Installed HBSS package"'
    - onlyif:
      - 'test $(rpm -qa | grep "{{ MSFEpkg }}")'

    {%- endif %}

notify_V{{ stig_id }}-notfound:
  cmd.run:
    - name: 'printf "** WARNING **\n  Could neither find installed HBSS\n  package nor install one.\n"'
    - unless:
      - 'test $(rpm -qa | grep "{{ MSFEpkg }}")'

{%- endif %}
