# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38657
# Finding ID:	V-38657
# Version:	RHEL-06-000273
# Finding Level:	Low
#
#     The system must use SMB client signing for connecting to samba 
#     servers using mount.cifs. Packet signing can prevent 
#     man-in-the-middle attacks which modify SMB packets in transit.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38657-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38657.sh

# Need to ID fstab-managed CIFS mounts then examine any hits
{% if salt['file.search']('/etc/fstab', 'cifs') %}
  # If any CIFS mounts are found, need to figure out a way to ID 
  # which are and which are not using secure mount options without 
  # getting any false hits or misses (especially when multiple CIFS 
  # mounts are present in fstab.  Possibly leverage iterate list 
  # produced by mount.fstab and verify mount-options via 
  # mount.mounted?
notify_V38657-notImp:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'
{% else %}
notify_V38657-noCIFS:
  cmd.run:
  - name: 'echo "No relevant finding: no CIFS mounts managed within /etc/fstab"'
{% endif %}

# Will want to check /etc/mtab and autofs configs, as well...
