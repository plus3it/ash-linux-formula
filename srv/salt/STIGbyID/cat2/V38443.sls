#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38443
# Finding ID:	V-38443
# Version:	RHEL-06-000036
# Finding Level:	Medium
#
#     The /etc/gshadow file must be owned by root. The "/etc/gshadow" file 
#     contains group password hashes. Protection of this file is critical 
#     for system security.
#
############################################################

script_V38443-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38443.sh

file_38443:
  file.managed:
  - name: /etc/gshadow
  - user: root
  - group: root
  - mode: 0000
