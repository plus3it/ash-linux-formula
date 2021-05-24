# Finding ID:	RHEL-07-040810
# Version:	RHEL-07-040810_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	The system must use a local firewall.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040810' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
# Stop iptables.service if running
service_{{ stig_id }}-dead:
  service.dead:
    - name: iptables

# Remove iptables.service if present
package_{{ stig_id }}-absent:
  pkg.removed:
    - name: iptables-services

# Install firewalld if absent
package_{{ stig_id }}-present:
  pkg.installed:
    - name: firewalld

# Start firewalld.service if running
service_{{ stig_id }}-running:
  service.running:
    - name: firewalld
    - enable: True
    - reload: True
    - watch:
      - pkg: 'package_{{ stig_id }}-present'
{%- endif %}
