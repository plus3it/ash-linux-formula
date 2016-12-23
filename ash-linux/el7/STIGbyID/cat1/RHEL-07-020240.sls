# Finding ID:	RHEL-07-020240
# Version:	RHEL-07-020240_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The operating system must be a supported release.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-020240' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

## Apparently, I shouldn't try to run an EL7 STIG-scanner against
## an EL 4 based host, I guess?
{%- if salt.grains.get('osmajorrelease') == '7' %}
goodtest_{{ stig_id }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''This test-suite valid against this target.''\n"'
    - cwd: /root
    - stateful: True
{%- else %}
goodtest_{{ stig_id }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''This test-suite not valid against this target.''\n"'
    - stateful: True
    - cwd: /root
{%- endif %}
