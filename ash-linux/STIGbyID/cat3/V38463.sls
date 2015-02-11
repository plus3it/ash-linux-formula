# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38463
# Finding ID:	V-38463
# Version:	RHEL-06-000003
# Finding Level:	Low
#
#     The system must use a separate file system for /var/log. Placing 
#     "/var/log" in its own partition enables better separation between log 
#     files and other files in "/var/".
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38463-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38463.sh

# Not really happy with how the standard mount.mounted handler deals with 
# updating the fstab. This is a bit of a hack to prevent entry-doubling, but
# need to flesh it out for additional use-cases.
{% if salt['file.search']('/etc/fstab', '[ 	]/var/log[ 	]') %}
mount_V38463-tmp:
  cmd.run:
    - name: 'echo "/var/log already mounted as its own filesystem"'
{% else %}
mount_V38463-tmp:
  cmd.run:
    - name: 'echo "Manual intervention required: create and mount a device as /var/log"'
{% endif %}
