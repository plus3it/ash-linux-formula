# STIG ID:	RHEL-07-010040
# Rule ID:	SV-86485r4_rule
# Vuln ID:	V-71861
# SRG ID:	SRG-OS-000023-GPOS-00006
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must display the approved Standard
#	Mandatory DoD Notice and Consent Banner before granting local
#	or remote access to the system via a graphical user logon.
#
# CCI-000048
#    NIST SP 800-53 :: AC-8 a
#    NIST SP 800-53A :: AC-8.1 (ii)
#    NIST SP 800-53 Revision 4 :: AC-8 a
#
#################################################################
{%- set stig_id = 'RHEL-07-010040' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pkgChk = 'dconf' %}
{%- set headerLabel = 'org/gnome/login-screen' %}
{%- set dconfHeader = '[' + headerLabel + ']' %}
{%- set dconfBanner = '/etc/dconf/db/local.d/01-banner-message' %}
{%- import_text 'ash-linux/el7/banner-consent_full-embedLF.txt' as bannerText %}

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
  {%- if salt.pkg.version(pkgChk) %}
exists_{{ stig_id }}-{{ dconfBanner }}:
  file.touch:
    - name: '{{ dconfBanner }}'
    - unless: 'test -e {{ dconfBanner }}'

secheader_{{ stig_id }}-{{ dconfBanner }}:
  file.replace:
    - name: '{{ dconfBanner }}'
    - pattern: '^\[{{ headerLabel }}\]'
    - repl: '{{ dconfHeader }}'
    - append_if_not_found: True
    - require:
      - file: exists_{{ stig_id }}-{{ dconfBanner }}

seccontent_{{ stig_id }}-{{ dconfBanner }}:
  file.replace:
    - name: '{{ dconfBanner }}'
    - pattern: '^[ 	]*banner-message-text=.*$'
    - repl: |-
        banner-message-text='{{ bannerText | replace("\\n", "\\\\n")}}'
    - append_if_not_found: True
    - not_found_content: |-
        {{ 'banner-message-text=\'' ~ bannerText ~ '\''}}
    - require:
      - file: secheader_{{ stig_id }}-{{ dconfBanner }}
    - unless: 'grep -F "{{ bannerText }}" {{ dconfBanner }}'
  {%- endif %}
{%- endif %}
