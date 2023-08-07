# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230368
# Rule ID:    SV-230368r810414_rule
# STIG ID:    RHEL-08-020220
# SRG ID:     SRG-OS-000077-GPOS-00045
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must be configured in the password-auth file to prohibit
#       password reuse for a minimum of five generations.
#
# References:
#   CCI:
#     - CCI-000200
#   NIST SP 800-53 :: IA-5 (1) (e)
#   NIST SP 800-53A :: IA-5 (1).1 (v)
#   NIST SP 800-53 Revision 4 :: IA-5 (1) (e)
#
###########################################################################
{%- set stig_id = 'RHEL-08-020220' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pwhistory_cfg_file = '/etc/security/pwhistory.conf' %}
{%- set pwhistory_remember = salt.pillar.get('ash-linux:lookup:pam_stuff:pwhistory_remember', 5) %}
{%- set pwhistory_retry = salt.pillar.get('ash-linux:lookup:pam_stuff:pwhistory_retry', 3) %}

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
Update PAM and AuthSelect:
  pkg.latest:
    - pkgs:
      - pam
      - authselect

Enable pam_pwhistory module in PAM:
  cmd.run:
    - name: authselect enable-feature with-pwhistory
    - cwd: /root
    - require:
      - pkg: 'Update PAM and AuthSelect'

Set pam_pwhistory memory to {{ pwhistory_remember }}:
  file.replace:
    - name: '{{ pwhistory_cfg_file }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG IDs RHEL-08-020220 and RHEL-08-020221
        remember = {{ pwhistory_remember }}
    - pattern: '^(#|)\s*(remember)(\s*=\s*).*'
    - repl: '\g<2>\g<3>{{ pwhistory_remember }}'
    - require:
      - cmd: 'Enable pam_pwhistory module in PAM'

Set pam_pwhistory retry to {{ pwhistory_retry }}:
  file.replace:
    - name: '{{ pwhistory_cfg_file }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG IDs RHEL-08-020220 and RHEL-08-020221
        remember = {{ pwhistory_retry }}
    - pattern: '^(#|)\s*(retry)(\s*=\s*).*'
    - repl: '\g<2>\g<3>{{ pwhistory_retry }}'
    - require:
      - cmd: 'Enable pam_pwhistory module in PAM'
{%- endif %}

