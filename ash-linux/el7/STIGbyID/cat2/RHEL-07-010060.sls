# STIG ID:	RHEL-07-010060
# Rule ID:	SV-86515r6_rule
# Vuln ID:	V-71891
# SRG ID:	SRG-OS-000028-GPOS-00009
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must enable a user session lock until that
#	user re-establishes access using established identification and
#	authentication procedures.
#
# CCI-000056
#    NIST SP 800-53 :: AC-11 b
#    NIST SP 800-53A :: AC-11.1 (iii)
#    NIST SP 800-53 Revision 4 :: AC-11 b
#
#################################################################
{%- set stig_id = 'RHEL-07-010060' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pkgName = 'dconf' %}
{%- set dconfDir = '/etc/dconf/db/local.d' %}
{%- set targVal = 'lock-enabled=true' %}
{%- set headerLabel = 'org/gnome/desktop/screensaver' %}
{%- set dconfHeader = '[' + headerLabel + ']' %}
{%- set dconfBanner = dconfDir + '/00-screensaver' %}


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
# Check if target RPM is installed
  {%- if salt.pkg.version(pkgName) %}
  # Check if a section-header is already present
    {%- if (
          salt.file.file_exists(dconfBanner) and
          salt.file.search(dconfBanner, '^\[' + headerLabel + '\]')
         ) %}
    # Check if a banner-message has already been specified
      {%- if salt.file.search(dconfBanner, targVal) %}
file_{{ stig_id }}-{{ dconfBanner }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Use of a session-lock already enabled.''\n"'
    - cwd: /root
    - stateful: True
      {%- else  %}
file_{{ stig_id }}-{{ dconfBanner }}:
  file.replace:
    - name: '{{ dconfBanner }}'
    - pattern: '^\[{{ headerLabel }}\]'
    - repl: |-
        {{ dconfHeader }}
        {{ targVal }}
      {%- endif  %}
    {%- else %}
file_{{ stig_id }}-{{ dconfBanner }}:
  file.append:
    - name: '{{ dconfBanner }}'
    - text: |-
        {{ dconfHeader }}
        {{ targVal }}
    {%- endif %}
  {%- else %}
  {%- endif %}
{%- endif %}
