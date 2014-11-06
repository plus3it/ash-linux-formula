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

mount_V38455-tmp:
  mount.mounted:
    - name: /tmp
    - device: tmpfs
    - fstype: tmpfs
    - mkmnt: True
    - opts:
      - defaults
{% if salt['file.search']('/etc/fstab', '[ 	]/tmp[ 	]') %}
    - persist: False
{% endif %}
