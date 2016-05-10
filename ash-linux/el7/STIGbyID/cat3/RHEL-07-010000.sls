# STIG URL:
# Finding ID:	RHEL-07-010000
# Version:	RHEL-07-010000_rule
# SRG ID:	SRG-OS-000001-GPOS-00001
# Finding Level:	low
#
# Rule Summary:
#     The operating system must provide automated mechanisms for 
#     supporting account management functions.
#
# CCI-000015
#    NIST SP 800-53 :: AC-2 (1)
#    NIST SP 800-53A :: AC-2 (1).1
#    NIST SP 800-53 Revision 4 :: AC-2 (1)
#
#################################################################
{%- set stig_id = 'RHEL-07-010000' %}
{%- set chkPkg = 'sssd-common' %}
{%- set chkSvc = 'sssd' %}
{%- set sssdConf = '/etc/sssd/sssd.conf' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt['pkg.version'](chkPkg) %}
# This is a purely informational test-action
  {%- if not salt['service.enabled'](chkSvc) %}
notify_{{ stig_id }}-enabled-{{ chkSvc }}:
  cmd.run:
    - name: "printf \"changed=no comment='The {{ chkSvc }} subsystem \" ;
             printf \"is not enabled.'\""
    - stateful: True
  {%- endif %}

  {%- if salt['file.file_exists'](sssdConf) %}
expire_{{ stig_id }}-{{ sssdConf }}:
  file.replace:
    - name: '{{ sssdConf }}'
    - pattern: 'offline_credentials_expiration.*$'
    - repl: 'offline_credentials_expiration = 1'
    - append_if_not_found: True

attempt_{{ stig_id }}-{{ sssdConf }}:
  file.replace:
    - name: '{{ sssdConf }}'
    - pattern: 'offline_failed_login_attempts.*$'
    - repl: 'offline_failed_login_attempts = 3'
    - append_if_not_found: True

delay_{{ stig_id }}-{{ sssdConf }}:
  file.replace:
    - name: '{{ sssdConf }}'
    - pattern: 'offline_failed_login_delay.*$'
    - repl: 'offline_failed_login_delay = 30'
    - append_if_not_found: True

  {%- else %}
append_{{ stig_id }}-{{ sssdConf }}:
  file.append:
    - name: '{{ sssdConf }}'
    - text: |
        offline_credentials_expiration = 1 
        offline_failed_login_attempts = 3 
        offline_failed_login_delay = 30 

setOwn_{{ stig_id }}-{{ sssdConf }}:
  file.managed:
    - name: '{{ sssdConf }}'
    - user: '{{ chkSvc }}'
    - group: '{{ chkSvc }}'
    - require:
      - file: append_{{ stig_id }}-{{ sssdConf }}

  {%- endif %}
{%- else %}
notify_{{ stig_id }}-presence-{{ chkPkg }}:
  cmd.run:
    - name: "printf \"changed=no comment='The {{ chkPkg }} subsystem \" ;
             printf \"is not installed.'\""
    - stateful: True
{%- endif %}

