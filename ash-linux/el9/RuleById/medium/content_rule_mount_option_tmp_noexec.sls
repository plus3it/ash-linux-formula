# Rule ID:              content_rule_mount_option_tmp_noexec
# Finding Level:        medium
#
# Rule Summary:
#       Ensure that the /tmp filesystem is mounted with the `noexec` option set
#
# Identifiers:
#   - content_rule_mount_option_tmp_noexec
#
# References:
#   - ANSSI
#     - BP28(R12)
#   - CIS-CSC
#     - 11
#     - 13
#     - 14
#     - 3
#     - 8
#     - 9
#   - COBIT5
#     - APO13.01
#     - BAI10.01
#     - BAI10.02
#     - BAI10.03
#     - BAI10.05
#     - DSS05.02
#     - DSS05.05
#     - DSS05.06
#     - DSS06.06
#   - DISA
#     - CCI-001764
#   - ISA-62443-2009
#     - 4.3.3.5.1
#     - 4.3.3.5.2
#     - 4.3.3.5.3
#     - 4.3.3.5.4
#     - 4.3.3.5.5
#     - 4.3.3.5.6
#     - 4.3.3.5.7
#     - 4.3.3.5.8
#     - 4.3.3.6.1
#     - 4.3.3.6.2
#     - 4.3.3.6.3
#     - 4.3.3.6.4
#     - 4.3.3.6.5
#     - 4.3.3.6.6
#     - 4.3.3.6.7
#     - 4.3.3.6.8
#     - 4.3.3.6.9
#     - 4.3.3.7.1
#     - 4.3.3.7.2
#     - 4.3.3.7.3
#     - 4.3.3.7.4
#     - 4.3.4.3.2
#     - 4.3.4.3.3
#   - ISA-62443-2013
#     - SR 1.1
#     - SR 1.10
#     - SR 1.11
#     - SR 1.12
#     - SR 1.13
#     - SR 1.2
#     - SR 1.3
#     - SR 1.4
#     - SR 1.5
#     - SR 1.6
#     - SR 1.7
#     - SR 1.8
#     - SR 1.9
#     - SR 2.1
#     - SR 2.2
#     - SR 2.3
#     - SR 2.4
#     - SR 2.5
#     - SR 2.6
#     - SR 2.7
#     - SR 7.6
#   - ISO27001-2013
#     - A.11.2.9
#     - A.12.1.2
#     - A.12.5.1
#     - A.12.6.2
#     - A.14.2.2
#     - A.14.2.3
#     - A.14.2.4
#     - A.8.2.1
#     - A.8.2.2
#     - A.8.2.3
#     - A.8.3.1
#     - A.8.3.3
#     - A.9.1.2
#   - NERC-CIP
#     - CIP-003-8 R5.1.1
#     - CIP-003-8 R5.3
#     - CIP-004-6 R2.3
#     - CIP-007-3 R2.1
#     - CIP-007-3 R2.2
#     - CIP-007-3 R2.3
#     - CIP-007-3 R5.1
#     - CIP-007-3 R5.1.1
#     - CIP-007-3 R5.1.2
#   - NIST
#     - CM-7(a)
#     - CM-7(b)
#     - CM-6(a)
#     - AC-6
#     - AC-6(1)
#     - MP-7
#   - NIST-CSF
#     - PR.IP-1
#     - PR.PT-2
#     - PR.PT-3
#   - OS-SRG
#     - SRG-OS-000368-GPOS-00154
#
#################################################################
{%- set stig_id = 'mount_option_tmp_noexec' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set OptsDefaultFile = '/usr/lib/systemd/system/tmp.mount' %}
{%- set mountOptsDefault = salt.cmd.shell(
    'grep -h ^Options= ' +
    OptsDefaultFile +
    ' | sed "s/Options=//"'
  ).split(',')
%}
{%- set mountOptsStig = [
  'noexec',
] %}
{%- set optionsDir = '/etc/systemd/system/tmp.mount.d' %}
{%- set optionsFile = optionsDir + '/options.conf' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}
           Set noexec mount-option on /tmp to
           prevent abuses.
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
# Ensure mount-options directory exists
Create {{ optionsDir }} ({{ stig_id }}):
  file.directory:
    - name: '{{ optionsDir }}'
    - group: 'root'
    - mode: '0700'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'systemd_unit_file_t'
        seuser: 'system_u'
    - unless:
      - [[ -d {{ optionsDir }} ]]
    - user: 'root'

# Ensure (dummy) mount-options file exists
Create Dummy {{ optionsFile }} ({{ stig_id }}):
  file.managed:
    - name: '{{ optionsFile }}'
    - contents: |-
        [Mount]
        Options=
    - dir_mode: '0755'
    - group: 'root'
    - makedirs: True
    - mode: '0644'
    - requires:
      - file: Create {{ optionsDir }} ({{ stig_id }})
    - unless:
      - '[[ -f {{ optionsFile }} ]]'
    - user: 'root'

# Ensure specified mount-option(s) present
  {%- for mntOpt in mountOptsDefault + mountOptsStig %}
Add first mount-option {{ mntOpt }} ({{ stig_id }}):
  file.replace:
    - name: '{{ optionsFile }}'
    - pattern: '^(Options=$)'
    - repl: '\1{{ mntOpt }}'
    - require:
      - file: Create Dummy {{ optionsFile }} ({{ stig_id }})

Add extra mount-option {{ mntOpt }} ({{ stig_id }}):
  file.replace:
    - name: '{{ optionsFile }}'
    - pattern: '^(Options=..*)'
    - repl: '\1,{{ mntOpt }}'
    - require:
      - file: Create Dummy {{ optionsFile }} ({{ stig_id }})
    - unless:
      - 'grep -q ^Options=.*{{ mntOpt }} {{ optionsFile }}'
      - file: Add first mount-option {{ mntOpt }} ({{ stig_id }})
  {%- endfor %}
{%- endif %}
