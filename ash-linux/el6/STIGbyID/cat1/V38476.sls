# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38476
# Finding ID:	V-38476
# Version:	RHEL-06-000008
# Finding Level:	High
#
#     Vendor-provided cryptographic certificates must be installed to 
#     verify the integrity of system software. The Red Hat GPG key is 
#     necessary to cryptographically verify packages are from Red Hat.
#
############################################################

{%- set stigId = 'V38476' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

cmd_{{ stigId }}:
  cmd.run:
  {%- if grains['os'] == 'RedHat' %}
    - name: 'rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep "Red Hat, Inc. (release key 2)"'
  {%- elif grains['os'] == 'CentOS' %}
    - name: 'rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep "CentOS 6 Official Signing Key"'
  {%- elif grains['os'] == 'Amazon' %}
    - name: 'rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep "Amazon Linux AMI (GA) <linux-security@amazon.com>"'
  {%- endif %}
