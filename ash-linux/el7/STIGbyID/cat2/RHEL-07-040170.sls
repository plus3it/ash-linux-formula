# Finding ID:	RHEL-07-040170
# Version:	RHEL-07-040170_rule
# SRG ID:	SRG-OS-000023-GPOS-00006
# Finding Level:	medium
#
# Rule Summary:
#	The Standard Mandatory DoD Notice and Consent Banner must be
#	displayed immediately prior to, or as part of, remote access
#	logon prompts.
#
# CCI-000048
# CCI-000050
# CCI-001384
# CCI-001385
# CCI-001386
# CCI-001387
# CCI-001388
#    NIST SP 800-53 :: AC-8 a
#    NIST SP 800-53A :: AC-8.1 (ii)
#    NIST SP 800-53 Revision 4 :: AC-8 a
#    NIST SP 800-53 :: AC-8 b
#    NIST SP 800-53A :: AC-8.1 (iii)
#    NIST SP 800-53 Revision 4 :: AC-8 b
#    NIST SP 800-53 :: AC-8 c
#    NIST SP 800-53A :: AC-8.2 (i)
#    NIST SP 800-53 Revision 4 :: AC-8 c 1
#    NIST SP 800-53 :: AC-8 c
#    NIST SP 800-53A :: AC-8.2 (ii)
#    NIST SP 800-53 Revision 4 :: AC-8 c 2
#    NIST SP 800-53 :: AC-8 c
#    NIST SP 800-53A :: AC-8.2 (ii)
#    NIST SP 800-53 Revision 4 :: AC-8 c 2
#    NIST SP 800-53 :: AC-8 c
#    NIST SP 800-53A :: AC-8.2 (ii)
#    NIST SP 800-53 Revision 4 :: AC-8 c 2
#    NIST SP 800-53 :: AC-8 c
#    NIST SP 800-53A :: AC-8.2 (iii)
#    NIST SP 800-53 Revision 4 :: AC-8 c 3
#
#################################################################
{%- set stig_id = 'RHEL-07-040170' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set svcName = 'sshd' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'Banner' %}
{%- set parmValu = '/etc/issue'%}

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
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^\s*{{ parmName }} .*$'
    - repl: '{{ parmName }} {{ parmValu }}'
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        {{ parmName }} {{ parmValu }}

    - append_if_not_found: True

service_{{ stig_id }}-{{ cfgFile }}:
  service.running:
    - name: '{{ svcName }}'
    - watch:
      - file: file_{{ stig_id }}-{{ cfgFile }}
{%- endif %}
