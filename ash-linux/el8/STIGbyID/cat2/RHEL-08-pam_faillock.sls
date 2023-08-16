# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-230333
#             V-230335
#             V-230337
#             V-230341
#             V-230343
#             V-244533
#             V-244534
#             V-244540
# Rule ID:    SV-230333r743966_rule
#             SV-230335r743969_rule
#             SV-230337r743972_rule
#             SV-230341r743978_rule
#             SV-230343r743981_rule
#             SV-244533r743848_rule
#             SV-244534r743851_rule
#             SV-245540r754730_rule
# STIG ID:    RHEL-08-010001
#             RHEL-08-020011
#             RHEL-08-020013
#             RHEL-08-020015
#             RHEL-08-020019
#             RHEL-08-020021
#             RHEL-08-020023
#             RHEL-08-020025
#             RHEL-08-020026
#             RHEL-08-020027
#             RHEL-08-030590
# SRG ID:     SRG-OS-000021-GPOS-00005
#             SRG-OS-000191-GPOS-00080
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must lock out user accounts after a three failures within a
#       fifteen minute interval. The account should stay locked until an
#       administrator manually unlocks the account.
#
# References:
#   CCI:
#     - CCI-000044
#       - NIST SP 800-53 :: AC-7 a
#       - NIST SP 800-53A :: AC-7.1 (ii)
#       - NIST SP 800-53 Revision 4 :: AC-7 a
#     - CCI-001233
#       - NIST SP 800-53 :: SI-2 (2)
#       - NIST SP 800-53A :: SI-2 (2).1 (ii)
#       - NIST SP 800-53 Revision 4 :: SI-2 (2)
#
###########################################################################
{%- set stig_id = 'RHEL-08-pam_faillock' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set authselect_profile = salt.pillar.get('ash-linux:lookup:pam_stuff:profile_name', 'sssd-hardened') %}
{%- set faillock_cfg_file = '/etc/security/faillock.conf' %}
{%- set faillock_deny_count = salt.pillar.get('ash-linux:lookup:pam_stuff:faillock_deny_count', 3) %}
{%- set faillock_fail_interval = salt.pillar.get('ash-linux:lookup:pam_stuff:faillock_fail_interval', 900) %}
{%- set faillock_unlock_time = salt.pillar.get('ash-linux:lookup:pam_stuff:faillock_unlock_time', 0) %}
{%- set faillock_logging_dir = salt.pillar.get('ash-linux:lookup:pam_stuff:faillock_logging_dir', '/var/log/faillock') %}

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
Update PAM and AuthSelect ({{ stig_id }}):
  pkg.latest:
    - pkgs:
      - pam
      - authselect

# STIG IDs RHEL-08-020025 and RHEL-08-020026
Enable pam_faillock module in PAM ({{ stig_id }}):
  cmd.run:
    - name: authselect enable-feature with-faillock
    - cwd: /root
    - onlyif:
      - 'authselect check'
    - unless:
      - 'authselect current | grep -q "with-faillock"'

# STIG ID RHEL-08-020011
Set pam_faillock deny-count to {{ faillock_deny_count }}:
  file.replace:
    - name: '{{ faillock_cfg_file }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG ID RHEL-08-020011
        deny = {{ faillock_deny_count }}
    - pattern: '^(#|)\s*(deny)(\s*=\s*).*'
    - repl: '\g<2>\g<3>{{ faillock_deny_count }}'
    - require:
      - cmd: 'Enable pam_faillock module in PAM ({{ stig_id }})'

# STIG ID RHEL-08-020013
Set pam_faillock fail_interval to {{ faillock_fail_interval }}:
  file.replace:
    - name: '{{ faillock_cfg_file }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG ID RHEL-08-020013
        fail_interval = {{ faillock_fail_interval }}
    - pattern: '^(#|)\s*(fail_interval)(\s*=\s*).*'
    - repl: '\g<2>\g<3>{{ faillock_fail_interval }}'
    - require:
      - cmd: 'Enable pam_faillock module in PAM ({{ stig_id }})'

# STIG ID RHEL-08-020015
Set pam_faillock unlock_time to {{ faillock_unlock_time }}:
  file.replace:
    - name: '{{ faillock_cfg_file }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG ID RHEL-08-020015
        unlock_time = {{ faillock_unlock_time }}
    - pattern: '^(#|)\s*(unlock_time)(\s*=\s*).*'
    - repl: '\g<2>\g<3>{{ faillock_unlock_time }}'
    - require:
      - cmd: 'Enable pam_faillock module in PAM ({{ stig_id }})'

# STIG ID RHEL-08-020019
Set pam_faillock enable silent:
  file.replace:
    - name: '{{ faillock_cfg_file }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG ID RHEL-08-020019
        silent
    - pattern: '^(#|)\s*(silent).*'
    - repl: '\g<2>'
    - require:
      - cmd: 'Enable pam_faillock module in PAM ({{ stig_id }})'

# STIG ID RHEL-08-020021
Set pam_faillock enable audit:
  file.replace:
    - name: '{{ faillock_cfg_file }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG ID RHEL-08-020021
        audit
    - pattern: '^(#|)\s*(audit).*'
    - repl: '\g<2>'
    - require:
      - cmd: 'Enable pam_faillock module in PAM ({{ stig_id }})'

# STIG ID RHEL-08-020023
Set pam_faillock enable even_deny_root:
  file.replace:
    - name: '{{ faillock_cfg_file }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG ID RHEL-08-020023
        even_deny_root
    - pattern: '^(#|)\s*(even_deny_root).*'
    - repl: '\g<2>'
    - require:
      - cmd: 'Enable pam_faillock module in PAM ({{ stig_id }})'

# STIG ID RHEL-08-020027
Ensure {{ faillock_logging_dir }} exists:
  file.directory:
    - name: {{ faillock_logging_dir }}
    - group: root
    - makedirs: True
    - mode: '0700'
    - require:
      - cmd: 'Enable pam_faillock module in PAM ({{ stig_id }})'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'faillog_t'
        seuser: 'unconfined_u'
    - user: root

# STIG ID RHEL-08-030590
Set pam_faillock logging dir to {{ faillock_logging_dir }}:
  file.replace:
    - name: '{{ faillock_cfg_file }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG ID RHEL-08-030590
        dir={{ faillock_logging_dir }}
    - pattern: '^(#\s*|.*)(dir)(\s*=\s*).*$'
    - repl: '\g<2>\g<3>{{ faillock_logging_dir }}'
    - require:
      - cmd: 'Enable pam_faillock module in PAM ({{ stig_id }})'
{%- endif %}
