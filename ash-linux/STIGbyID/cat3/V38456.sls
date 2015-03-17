# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38456
# Finding ID:	V-38456
# Version:	RHEL-06-000002
# Finding Level:	Low
#
#     Ensuring that "/var" is mounted on its own partition enables the 
#     setting of more restrictive mount options. This helps protect system 
#     services such as daemons or other programs which use it. It is not 
#     uncommon for the "/var" directory to contain world-writable 
#     directories, installed by other software packages. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38456-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38456.sh
    - cwd: /root

# Not really happy with how the standard mount.mounted handler deals with 
# updating the fstab. This is a bit of a hack to prevent entry-doubling, but
# need to flesh it out for additional use-cases.
{%- if salt['file.search']('/etc/fstab', '[ 	]/var[ 	]') %}
mount_V38456-tmp:
  cmd.run:
    - name: 'echo "/var already mounted as its own filesystem"'
{%- else %}
mount_V38456-tmp:
  cmd.run:
    - name: 'echo "Manual intervention required: create and mount a device as /var"'
{%- endif %}
