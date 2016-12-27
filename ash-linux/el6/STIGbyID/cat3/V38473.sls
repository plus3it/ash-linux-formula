# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38473
# Finding ID:	V-38473
# Version:	RHEL-06-000007
# Finding Level:	Low
#
#     Ensuring that "/home" is mounted on its own partition enables the 
#     setting of more restrictive mount options, and also helps ensure that 
#     users cannot trivially fill partitions used for log or audit data 
#     storage. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38473' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Not really happy with how the standard mount.mounted handler deals with 
# updating the fstab. This is a bit of a hack to prevent entry-doubling, but
# need to flesh it out for additional use-cases.
{%- if salt.file.search('/etc/fstab', '[ 	]/home[ 	]') %}
mount_{{ stigId }}-tmp:
  cmd.run:
    - name: 'echo "/home already mounted as its own filesystem"'
{%- else %}
mount_{{ stigId }}-tmp:
  cmd.run:
    - name: 'echo "Manual intervention required: create and mount a device as /home"'
{%- endif %}
