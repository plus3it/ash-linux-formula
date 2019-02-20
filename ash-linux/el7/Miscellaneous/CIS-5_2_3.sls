# Rule Name:    sshd_set_loglevel_info
# CIS Rule ID:  5.2.3
#
# Summary:
#
#    SSH provides several logging levels with varying amounts of
#    verbosity. DEBUG is specifically not recommended other than
#    strictly for debugging SSH communications since it provides
#    so much data that it is difficult to identify important
#    security information. INFO level is the basic level that
#    only records login activity of SSH users. In many
#    situations, such as Incident Response, it is important to
#    determine when a particular user was active on a system. The
#    logout record can eliminate those users who disconnected,
#    which helps narrow the field.
#
#    Note: The EL7 SSHD defaults the value for the LogLevel 
#    parameter to be `INFO`. This state is simply designed to
#    help reduce false alerts caused by scan profiles that fail
#    to properly identify this defaulted posture.
#
#################################################################
{%- set helperLoc = 'ash-linux/el7/Miscellaneous/files' %}
{%- set statename = 'CIS-5_2_3' %}
{%- set svcName = 'sshd' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'LogLevel' %}
{%- set parmValu = salt.pillar.get('ash-linux:lookup:sshd-loglevel', 'INFO') %}

script_{{ statename }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ statename }}.sh
    - cwd: /root

file_{{ statename }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^\s*{{ parmName }} .*$'
    - repl: '{{ parmName }} {{ parmValu }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per CIS 5.2.3
        {{ parmName }} {{ parmValu }}

service_{{ statename }}-{{ cfgFile }}:
  service.running:
    - name: '{{ svcName }}'
    - watch:
      - file: file_{{ statename }}-{{ cfgFile }}
