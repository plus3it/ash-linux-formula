# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38655
# Rule ID:              mount_option_noexec_removable_partitions
# Finding ID:		V-38655
# Version:		RHEL-06-000271
# SCAP Security ID:	CCE-27196-5
# Finding Level:	Low
#
#     The noexec option must be added to removable media partitions.
#     Allowing users to execute binaries from removable media such as USB
#     keys exposes the system to potential compromise.
#
#  CCI: CCI-000087
#  NIST SP 800-53 :: AC-19 e
#  NIST SP 800-53A :: AC-19.1 (v)
#
# Note:
# * Fix suggested in STIG URL is overly-broad and doesn't particularly   #
#   address removable media. Removable media is generally handled though #
#   methods other than /etc/fstab (e.g., Gnome media manager)            #
# * Test suggested in STIG URL only applicable if not using the dynamic  #
#   media managers for removable media (not normal/recommended method).  #
#   This will create a false-finding on systems that either are not      #
#   configured to handle removable media or handle via dynamic media     #
#   manager utilities.                                                   #
#
############################################################

{%- set stigId = 'V38655' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

####################################
# Disable USB support (if enabled)
####################################
{%- set usbConf = '/etc/modprobe.d/usb.conf' %}

file-{{ stigId }}-touchUSBconf:
  file.touch:
    - name: {{ usbConf }}

file_{{ stigId }}-appendUSBconf:
  file.append:
    - name: {{ usbConf }}
    - text: 'install usb-storage /bin/true'
    - require:
      - file: file-{{ stigId }}-touchUSBconf
    - onlyif:
      - 'test -f {{ usbConf }}'

####################################################################
# Define list of filesystem types that are normally only found on
# mounted media devices
####################################################################
{%- set mediaFStypes = 'iso9660 ntfs udf msdos fat vfat' %}
{%- set pseudoFStypes = 'tmpfs proc sysfs selinuxfs usbfs devpts devtmpfs binfmt_misc' %}
{%- set NASfstypes = 'nfs cifs' %}
{%- set ignoreFStypes = pseudoFStypes + ' ' + NASfstypes %}

# Ingest list of mounted filesystems into a searchable-structure
{%- set activeMntStream = salt['mount.active']('extended=true') %}

# Ingest list of fstab-managed filesystems into a searchable-structure
{%- set fstabMntStream = salt['mount.fstab']() %}
{%- set fstabMntList = fstabMntStream.keys() %}

######################################
## Check/fix fstab-managed mounts
######################################
notify_{{ stigId }}-fstabScan:
  cmd.run:
    - name: 'echo "Scanning for fstab-managed media devices..."'

# Ingest list of fstab-managed filesystems into a searchable-structure
{%- set fstabMntStream = salt['mount.fstab']() %}
{%- set fstabMntList = fstabMntStream.keys() %}

# Iterate the structure by top-level key
{%- for fstabMount in fstabMntList %}

{%- set fstabMountStruct = fstabMntStream[fstabMount] %}

# Pull fstype value from key-value dictionary
{%- set fstabfsType = fstabMountStruct['fstype'] %}
{%- set fstabMountOpts = fstabMountStruct['opts'] %}

{%- if fstabfsType in mediaFStypes %}
  {%- if 'noexec' in fstabMountOpts %}
notify_{{ stigId }}-{{ fstabMount }}_fstabMntOpt:
  cmd.run:
    - name: 'echo "Info: Mountpount ''{{ fstabMount }}'' has ''noexec'' option set"'
  {%- else %}
{%- set remountDev = fstabMountStruct['device'] %}
{%- set optString = fstabMountOpts|join(' ') + ',noexec' %}

notify_{{ stigId }}-{{ fstabMount }}_fstabMntOpt:
  cmd.run:
    - name: 'printf "
WARNING: Mountpount ''{{ fstabMount }} does not have\n
''noexec'' option set ...changing\n
"'
fstab_{{ stigId }}-{{ fstabMount }}:
  module.run:
    - name: 'mount.set_fstab'
    - m_name: '{{ fstabMount }}'
    - device: '{{ remountDev }}'
    - fstype: '{{ fstabfsType }}'
    - opts: '{{ optString }}'

  {%- endif %}
{%- endif %}
{%- endfor %}


####################################
## Check/fix active mounts
####################################
notify_{{ stigId }}-mountScan:
  cmd.run:
    - name: 'echo "Scanning for mounted media devices..."'

# Iterate the structure by top-level key
{%- for mountPoint in activeMntStream.keys() %}

# Unpack key values out to searchable dictionary
{%- set mountList = activeMntStream[mountPoint] %}

# Pull device value from key-value dictionary
{%- set remountDev = mountList['device'] %}

# Pull fstype value from key-value dictionary
{%- set fsType = mountList['fstype'] %}

# Get and extend mount options-list
{%- set mountOpts = mountList['opts'] %}
{%- set remountOptString = mountOpts|join(',') + ',noexec' %}

{%- set fstabList = fstabMntList|join(' ') %}

# Check if mounted filesystem is of a targeted type
{%- if fsType in mediaFStypes %}

  # See if mounted filesystem is fstab-managed
  {%- if mountPoint in fstabList %}
crosscheck_{{ stigId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'printf "Info: ''{{ mountPoint }}'' defined in /etc/fstab\n\n"'
  {%- else %}
crosscheck_{{ stigId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'printf "WARNING: ''{{ mountPoint }}'' ({{ fsType }}) not defined in /etc/fstab\n"'
  {%- endif %}

  # See if mounted filesystem has 'noexec' opton set
  {%- if 'noexec' in mountOpts %}
notify_{{ stigId }}-{{ mountPoint }}_remount:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' has ''noexec'' option set"'
  {%- else %}
notify_{{ stigId }}-{{ mountPoint }}_remount:
  cmd.run:
    - name: 'echo "NOTICE: ''{{ mountPoint }}'' does not have ''noexec'' option set ...remounting"'

remount_{{ stigId }}-{{ mountPoint }}:
  module.run:
    - name: 'mount.remount'
    - m_name: '{{ mountPoint }}'
    - device: '{{ remountDev }}'
    - fstype: '{{ fsType }}'
    - opts: '{{ remountOptString }}'
  {%- endif %}
{%- endif %}

{%- endfor %}
