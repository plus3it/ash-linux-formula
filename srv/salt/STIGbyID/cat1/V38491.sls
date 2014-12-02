# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38491
# Finding ID:	V-38491
# Version:	RHEL-06-000019
# Finding Level:	High
#
#     There must be no .rhosts or hosts.equiv files on the system. Trust 
#     files are convenient, but when used in conjunction with the 
#     R-services, they can allow unauthenticated access to a system.
#
############################################################

script_V38491-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38491.sh

{% set hostsEquiv = '/etc/hosts.equiv' %}

{% if salt['file.file_exists'](hostsEquiv) %}
file_V38491-hostsEquiv:
  file.absent:
  - name: {{ hostsEquiv }}
{% else %}
file_V38491-hostsEquiv:
  cmd.run:
  - name: 'echo "No ''{{ hostsEquiv }}'' file found"'
{% endif %}


# Might be able to make this cleaner by using salt-based user lookup
# and *only* look for .rhosts files in each found user's defined home 
# directory
cmd_V38491-rhosts:
  cmd.run:
  - name: 'find / \( -fstype ext4 -o -fstype ext3 \) -type f -name .rhosts -exec rm {} \;'
  - onlyif: 'find / \( -fstype ext4 -o -fstype ext3 \) -type f -name .rhosts -print > /tmp/narf && test -s /tmp/narf'

