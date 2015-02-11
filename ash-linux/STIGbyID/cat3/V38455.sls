# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38455
# Finding ID:	V-38455
# Version:	RHEL-06-000001
# Finding Level:	Low
#
#     The "/tmp" partition is used as temporary storage by many programs. 
#     Placing "/tmp" in its own partition enables the setting of more 
#     restrictive mount options, which can help protect programs which use 
#     it. 
#
############################################################

script_V38455-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38455.sh

# Not really happy with how the standard mount.mounted handler deals with 
# updating the fstab. This is a bit of a hack to prevent entry-doubling, but
# need to flesh it out for additional use-cases.
{% if salt['file.search']('/etc/fstab', '[ 	]/tmp[ 	]') %}
mount_V38455-tmp:
   cmd.run:
     - name: 'echo "/tmp already mounted as its own filesystem"'
{% else %}
mount_V38455-tmp:
  mount.mounted:
    - name: /tmp
    - device: tmpfs
    - fstype: tmpfs
    - mkmnt: True
    - opts:
      - defaults
{% endif %}
