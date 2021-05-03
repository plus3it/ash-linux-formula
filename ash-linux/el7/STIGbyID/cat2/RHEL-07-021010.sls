# Finding ID:	RHEL-07-021010
# Version:	RHEL-07-021010_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	Files systems that contain user home directories must be
#	mounted to prevent files with the setuid and setgid bit set
#	from being executed.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021010' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set fstabMnts = salt.mount.fstab() %}
{%- set wantOpt = 'nosuid' %}
{%- set protMnts = [
                    '/',
                    '/usr',
                    '/usr/bin',
                    '/usr/local/bin',
                    '/var'
                     ] %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{ IDVAL = $2 + 1} END { print IDVAL }' /etc/login.defs
")|int %}
{%- set iShells = [
                   '/bin/sh',
                   '/bin/bash',
                   '/bin/csh',
                   '/bin/ksh',
                   '/bin/mksh',
                   '/bin/tcsh',
                   '/bin/zsh',
                   '/usr/bin/sh',
                   '/usr/bin/bash',
                   '/usr/bin/csh',
                   '/usr/bin/ksh',
                   '/usr/bin/mksh',
                   '/usr/bin/tcsh',
                   '/usr/bin/zsh'
                    ] %}
{%- set homeDevs = [] %}
{%- set userList = salt.user.list_users() %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
# Iterate local user-list
  {%- for user in userList %}
    {%- set uinfo = salt.user.info(user) %}
  # Regular interactive-users will have UID > SYS_USER_MAX and
  # will have an interactive shell assigned.
    {%- if ( uinfo['uid'] > sysuserMax ) and
         ( uinfo['shell'] in iShells ) %}
      {%- set uhome = uinfo['home'] %}
      {%- set homeMount = salt['cmd.shell']('df --output=target ' + uinfo['home'] + ' 2> /dev/null | tail -1') %}
      {%- if not homeMount in homeDevs %}
        {%- do homeDevs.append(homeMount) %}
      {%- endif %}
    {%- endif %}
  {%- endfor %}

  {%- if homeDevs %}
    {%- for homeDev in homeDevs %}
      {%- set mntOpts = fstabMnts[homeDev]['opts'] %}
      {%- if not wantOpt in mntOpts and
           not homeDev in protMnts %}
        {%- do mntOpts.append(wantOpt) %}
        {%- set fstabDevice = fstabMnts[homeDev]['device'] %}
        {%- set fstabDump = fstabMnts[homeDev]['dump'] %}
        {%- set fstabFstype = fstabMnts[homeDev]['fstype'] %}
        {%- set fstabPass =  fstabMnts[homeDev]['pass'] %}

fix_{{ stig_id }}-{{ homeDev }}:
  module.run:
    - name: 'mount.set_fstab'
    - m_name: '{{ homeDev }}'
    - device: '{{ fstabDevice }}'
    - fstype: '{{ fstabFstype }}'
    - opts: '{{ mntOpts|join(",") }}'
    - dump: '{{ fstabDump }}'
    - pass_num: '{{ fstabPass }}'
      {%- else %}
fix_{{ stig_id }}-{{ homeDev }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ homeDev }} already has {{ wantOpt }} option set: state ok.''\n"'
    - cwd: /root
    - stateful: True
      {%- endif %}
    {%- endfor %}
  {%- endif %}
{%- endif %}
