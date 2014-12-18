# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38652
# Finding ID:	V-38652
# Version:	RHEL-06-000269
# Finding Level:	Medium
#
#     Remote file systems must be mounted with the nodev option. Legitimate 
#     device files should only exist in the /dev directory. NFS mounts 
#     should not present device files to users.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38652-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38652.sh

cmd_V38652-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

# From `salt-call --no-color --local mount.active extended=true`
#   /var/log/audit:  <---------------------------- Mount Point
#       ----------
#       alt_device:  <---------------------------- Device-node
#           /dev/mapper/VolGroup00-auditVol
#       device:  <-------------------------------- Device-node
#           /dev/mapper/VolGroup00-auditVol
#       device_uuid:  <--------------------------- Device UUID
#           48431692-f9ae-4071-bf0e-c3ee42991027
#       fstype:  <-------------------------------- Filesystem Type
#           ext4
#       major:  <--------------------------------- Device Major
#           253
#       minor:  <--------------------------------- Device Minor
#           2
#       mountid:  <------------------------------- Mount ID
#           26
#       opts:  <---------------------------------- Default Mount Options
#           - rw
#           - relatime
#       parentid:  <------------------------------ Mount ID of parent filesystem
#           25
#       root:  <---------------------------------- Device-root
#           /
#       superopts:  <----------------------------- 
#           - rw
#           - seclabel
#           - acl
#           - barrier=1
#           - data=ordered

{% set activeMntStream = salt['mount.active']('extended=true') %}
{% for key,data in activeMntStream.items() %}
{% set mountPoint = key %}
{% set fsType = activeMntStream['fstype'] %}
notify_V38652-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "{{ mountPoint }}"'

{% endfor %}

