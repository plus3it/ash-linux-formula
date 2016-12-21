# Finding ID:	RHEL-07-040740
# Version:	RHEL-07-040740_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The Network File System (NFS) must be configured to use AUTH_GSS.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040740' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/fstab' %}
{%- set chkPkg = 'nfs-utils' %}
{%- set secopts = 'sec=krb5:krb5i:krb5p' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-break:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - cwd: /root
    - stateful: True
{%- elif not salt.pkg.version(chkPkg) %}
notify_{{ stig_id }}-break:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''NFS client utilities ({{ chkPkg }}) not installed: skipping.''\n"'
    - cwd: /root
    - stateful: True
{%- else %}
  {%- set fstabData = salt.mount.fstab() %}
  {%- for mount in fstabData.keys() %}
    {%- if fstabData[mount]['fstype'] == 'nfs' %}
      {%- set devName = fstabData[mount]['device'] %}
      {%- set dumpOpt = fstabData[mount]['dump'] %}
      {%- set fstype  = fstabData[mount]['fstype'] %}
      {%- set optStr  = fstabData[mount]['opts']|join(',') + ',' + secopts %}
      {%- set mntOpts = optStr.split(',') %}
      {%- set passNum = fstabData[mount]['pass'] %}
      {%- if secopts in fstabData[mount]['opts'] %}
fixopts_{{ stig_id }}-{{ mount }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Mountpoint {{ mount }} already has KRB5 mount-options set: state ok.''\n"'
    - cwd: /root
    - stateful: True
      {%- else %}
fixopts_{{ stig_id }}-{{ mount }}:
  module.run:
    - name: mount.set_fstab
    - m_name: '{{ mount }}'
    - device: '{{ devName }}'
    - fstype: '{{ fstype }}'
    - opts: '{{ optStr }}'
    - dump: '{{ dumpOpt }}'
    - pass_num: '{{ passNum }}'
    - cwd: /root
      {%- endif %}
    {%- endif %}
  {%- endfor %}
{%- endif %}
