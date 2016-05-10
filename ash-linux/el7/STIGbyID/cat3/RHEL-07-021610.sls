# STIG URL:
# Finding ID:	RHEL-07-021610
# Version:	RHEL-07-021610_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The file integrity tool must be configured to verify extended 
#     attributes.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021610' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set chkPkg = 'aide' %}
{%- set chkCfg = '/etc/aide.conf' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

pkg_{{ stig_id }}-{{ chkPkg }}:
  pkg.installed:
    - name: '{{ chkPkg }}'

vrfy_{{ stig_id }}-{{ chkPkg }}:
  cmd.script:
    - name: '{{ stig_id }}-check_fix.sh "{{ chkPkg }}" "{{ chkCfg }}"'
    - source: 'salt://{{ helperLoc }}/{{ stig_id }}-check_fix.sh'
    - cwd: '/root'
    - stateful: True
    - require:
      - pkg: pkg_{{ stig_id }}-{{ chkPkg }}

