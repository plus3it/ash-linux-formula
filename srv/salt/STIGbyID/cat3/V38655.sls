# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38655
# Finding ID:	V-38655
# Version:	RHEL-06-000271
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

script_V38655-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38655.sh

{% set modprobConf = '/etc/modprobe.conf' %}
{% set usbConf = '/etc/modprobe.d/usb.conf' %}

# Check if USB is enabled - notify if disabled
{% if salt['file.file_exists'](usbConf) or salt['file.file_exists'](modprobConf) %}
  {% if salt['file.search'](usbConf, 'install usb-storage /bin/true') or salt['file.search'](modprobConf, 'install usb-storage /bin/true') %}
notify_V38655-usbDisabled:
  cmd.run:
  - name: 'echo "Mounting of USB devices disabled"'
  {% endif %}
{% else %}
file-V38655-touchUSBconf:
  file.touch:
  - name: {{ usbConf }}

file_V38655-appendUSBconf:
  file.append:
  - name: {{ usbConf }}
  - text: 'install usb-storage /bin/true'
{% endif %}

# Probaby better way of detecting these...:
# * use salt['mount.fstab'] to load /etc/fstab into iterable list
# * iterate and look for non root-VG elements that are not pseudo-devices
#   and set 'noexec' option
# ?

# Check for /dev/cdrom/ or /dev/floppy/ devices
{% if salt['file.search']('/etc/fstab', '^/dev/cdrom') or salt['file.search']('/etc/fstab', '^/dev/floppy') %}
  {% if salt['file.search']('/etc/fstab', '^/dev/cdrom.*noexec') or salt['file.search']('/etc/fstab', '^/dev/floppy.*noexec') %}
notify_V38655-mediaNoxec:
  cmd.run:
  - name: 'echo "The noexec option already set for cdrom or floppy devs found in fstab"'
  {% else %}
notify_V38655-mediaNoexec:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED: adding noexec option to floppy/cdrom mounts"'
  {% endif %}
{% else %}
notify_V38655-mediaNoexec:
  cmd.run:
  - name: 'echo "No cdrom or floppy devs found in fstab"'
{% endif %}

# Check for iso9660s on other dev-paths
{% if salt['file.search']('/etc/fstab', '^[/L].*[ 	]*iso9660[ 	]')  %}
notify_V38655-isoNoexec:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED: adding noexec option to iso9660 mounts"'
{% endif %}

# Check for vfat on other dev-paths
{% if salt['file.search']('/etc/fstab', '^[/L].*[ 	]*vfat[ 	]')  %}
notify_V38655-vfatNoexec:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED: adding noexec option to vfat mounts"'
{% endif %}

# Check for msdos on other dev-paths
{% if salt['file.search']('/etc/fstab', '^[/L].*[ 	]*msdos[ 	]')  %}
notify_V38655-msdosNoexec:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED: adding noexec option to msdos mounts"'
{% endif %}


cmd_V38655-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED: test and fix for non-USB mountable media"'

