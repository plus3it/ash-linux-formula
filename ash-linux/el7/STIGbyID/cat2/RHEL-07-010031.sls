# Finding ID:	RHEL-07-010031
# Version:	RHEL-07-010031_rule
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
{%- set stig_id = 'RHEL-07-010031' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pkgChk = 'dconf' %}
{%- set headerLabel = 'org/gnome/login-screen' %}
{%- set dconfHeader = '[' + headerLabel + ']' %}
{%- set dconfBanner = '/etc/dconf/db/local.d/01-banner-message' %}
{%- import_text 'ash-linux/el7/banner-consent_full.txt' as bannerText %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Check if target RPM is installed
{%- if salt.pkg.version(pkgChk) %}
  # Check if a section-header is already present
  {%- if salt.file.search(dconfBanner, '^\[' + headerLabel + '\]') %}
    # Check if a banner-message has already been specified
    {%- if salt.file.search(dconfBanner, 'banner-message-text=') %}
file_{{ stig_id }}-{{ dconfBanner }}:
  cmd.run:
    - name: 'echo "A ''banner-message-text'' value has been defined"'
    - cwd: /root
    {%- else  %}
file_{{ stig_id }}-{{ dconfBanner }}:
  file.replace:
    - name: '{{ dconfBanner }}'
    - pattern: '^\[{{ headerLabel }}\]'
    - repl: |
        {{ dconfHeader }}
        {{ 'banner-message-text=\'' ~ bannerText | indent(8) ~ '\'' }}
    {%- endif  %}
  {%- else %}
file_{{ stig_id }}-{{ dconfBanner }}:
  file.append:
    - name: '{{ dconfBanner }}'
    - text: |
        {{ dconfHeader }}
        {{ 'banner-message-text=\'' ~ bannerText | indent(8) ~ '\'' }}
  {%- endif %}
{%- else %}
{%- endif %}
