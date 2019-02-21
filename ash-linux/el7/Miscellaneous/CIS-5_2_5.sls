# Rule Name:    sshd_set_max_auth_tries
# CIS Rule ID:  5.2.5
#
# Summary:
#
#    The MaxAuthTries parameter specifies the maximum number of
#    authentication attempts permitted per connection. When the
#    login failure count reaches half the number, error messages
#    will be written to the syslog file detailing the login
#    failure.
#
#    Setting the MaxAuthTries parameter to a low number will
#    minimize the risk of successful brute force attacks to the
#    SSH server. While the recommended setting is 4, set the
#    number based on site policy.
#
#    Note: Mostly obviated by the STIG-mandated modifications to
#    the PAM subsystem. Included for scanners that include CIS-
#    recommended settings that are not part of the STIGs
#
#################################################################
{%- set helperLoc = 'ash-linux/el7/Miscellaneous/files' %}
{%- set statename = 'CIS-5_2_5' %}
{%- set svcName = 'sshd' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'MaxAuthTries' %}
{%- set parmValu = salt.pillar.get('ash-linux:lookup:sshd-maxTries', '4') %}

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
        # Inserted per CIS 5.2.5
        {{ parmName }} {{ parmValu }}

service_{{ statename }}-{{ cfgFile }}:
  service.running:
    - name: '{{ svcName }}'
    - watch:
      - file: file_{{ statename }}-{{ cfgFile }}
