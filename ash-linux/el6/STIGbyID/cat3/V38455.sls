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

{%- set stigId = 'V38455' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set chkFile = '/etc/fstab' %}
{%- set chkPtn = '/tmp' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Not really happy with how the standard mount.mounted handler deals with 
# updating the fstab. This is a bit of a hack to prevent entry-doubling, but
# need to flesh it out for additional use-cases.
{%- if salt.file.search(chkFile, '[ 	]' + chkPtn + '[ 	]') %}
mount_{{ stigId }}-{{ chkPtn }}:
  cmd.run:
    - name: 'echo "{{ chkPtn }} already mounted as its own filesystem"'
{%- else %}
mount_{{ stigId }}-{{ chkPtn }}:
  mount.mounted:
    - name: '{{ chkPtn }}'
    - device: tmpfs
    - fstype: tmpfs
    - mkmnt: True
    - opts:
      - defaults
{%- endif %}
