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

{%- set stigId = 'V38456' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set chkFile = '/etc/fstab' %}
{%- set chkPtn = '/var' %}

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
  cmd.run:
    - name: 'echo "Manual intervention required: create and mount a device as {{ chkPtn }}"'
{%- endif %}
