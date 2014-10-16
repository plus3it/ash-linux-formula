#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38472
# Finding ID:	V-38472
# Version:	RHEL-06-000048
# Finding Level:	Medium
#
#     All system command files must be owned by root. System binaries are 
#     executed by privileged users as well as system services, and 
#     restrictive permissions are necessary to ensure that their execution 
#     of these programs cannot be co-opted.
#
############################################################

cript_V38472-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38472.sh

file_V38466-bin:
  file.directory:
  - name: /bin
  - user: root
  - recurse:
    - user

file_V38466-ubin:
  file.directory:
  - name: /usr/bin
  - user: root
  - recurse:
    - user

file_V38466-lbin:
  file.directory:
  - name: /usr/local/bin
  - user: root
  - recurse:
    - user

file_V38466-sbin:
  file.directory:
  - name: /sbin
  - user: root
  - recurse:
    - user

file_V38466-usbin:
  file.directory:
  - name: /usr/sbin
  - user: root
  - recurse:
    - user

file_V38466-lsbin:
  file.directory:
  - name: /usr/local/sbin
  - user: root
  - recurse:
    - user
