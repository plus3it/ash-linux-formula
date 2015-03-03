# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38467
# Finding ID:	V-38467
# Version:	RHEL-06-000004
# Finding Level:	Low
#
#     The system must use a separate file system for the system audit data 
#     path. Placing "/var/log/audit/audit" in its own partition enables better 
#     separation between audit files and other files, and helps ensure that 
#     auditing cannot be halted due to the partition running out of space.
#
#  CCI: CCI-000137
#  NIST SP 800-53 :: AU-4
#  NIST SP 800-53A :: AU-4.1 (i)
#
############################################################

script_V38467-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38467.sh
    - cwd: /root

# Not really happy with how the standard mount.mounted handler deals with 
# updating the fstab. This is a bit of a hack to prevent entry-doubling, but
# need to flesh it out for additional use-cases.
{% if salt['file.search']('/etc/fstab', '[ 	]/var/log/audit[ 	]') %}
mount_V38467-tmp:
   cmd.run:
     - name: 'echo "/var/log/audit already mounted as its own filesystem"'
{% else %}
mount_V38467-tmp:
   cmd.run:
     - name: 'echo "Manual intervention required: create and mount a device as /var/log/audit"'
{% endif %}
