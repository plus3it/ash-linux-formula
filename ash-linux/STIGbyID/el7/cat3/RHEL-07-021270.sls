# STIG URL:
# Finding ID:	RHEL-07-021270
# Version:	RHEL-07-021270_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The system must use a separate file system for /tmp (or 
#     equivalent).
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021270' %}
{%- set helperLoc = 'ash-linux/STIGbyID/el7/cat3/files' %}
{%- set chkPtn = '/tmp' %}
{%- set chkSvc = 'tmp.mount' %}
{%- set chkFile = '/etc/fstab' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt['file.contains'](chkFile, chkPtn) %}
cmd_{{ stig_id }}-managed_by:
  cmd.run:
    - name: 'echo "{{ chkPtn }} managed via {{ chkFile }}"'
{%- elif salt['service.status'](chkSvc) %}
cmd_{{ stig_id }}-managed_by:
  cmd.run:
    - name: 'echo "{{ chkPtn }} managed via {{ chkSvc }} systemd service"'
{%- else %}
cmd_{{ stig_id }}-managed_by:
  cmd.run:
    - name: 'echo "{{ chkPtn }} is not a mounted filesystem. Attempting to enable as tmpfs..."'

svc_{{ stig_id }}-unmask:
  module.run:
    - name: service.unmask
    - m_name: '{{ chkSvc }}'
    - requires: cmd.cmd_{{ stig_id }}-managed_by

svc_{{ stig_id }}-enable:
  module.run:
    - name: service.enable
    - m_name: '{{ chkSvc }}'
    - requires: module.svc_{{ stig_id }}-unmask

svc_{{ stig_id }}-start:
  module.run:
    - name: service.start
    - m_name: '{{ chkSvc }}'
    - requires: module.svc_{{ stig_id }}-enable
{%- endif %}
