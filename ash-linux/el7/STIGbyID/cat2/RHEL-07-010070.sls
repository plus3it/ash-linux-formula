# Finding ID:	RHEL-07-010070
# Version:	RHEL-07-010070_rule
# SRG ID:	SRG-OS-000029-GPOS-00010
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must initiate a screensaver after a
#	15-minute period of inactivity for graphical user interfaces.
#
# CCI-000057 
#    NIST SP 800-53 :: AC-11 a 
#    NIST SP 800-53A :: AC-11.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-11 a 
#
#################################################################
{%- set stig_id = 'RHEL-07-010070' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pkgName = 'dconf' %}
{%- set dconfDir = '/etc/dconf/db/local.d' %}
{%- set targVal = 'idle-delay=uint32 900' %}
{%- set headerLabel = 'org/gnome/desktop/screensaver' %}
{%- set dconfHeader = '[' + headerLabel + ']' %}
{%- set dconfBanner = dconfDir + '/00-screensaver' %}


script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Check if target RPM is installed
{%- if salt.pkg.version(pkgName) %}
  # Check if a section-header is already present
  {%- if salt.file.search(dconfBanner, '^\[' + headerLabel + '\]') %}
    # Check if a banner-message has already been specified
    {%- if salt.file.search(dconfBanner, targVal) %}
file_{{ stig_id }}-{{ dconfBanner }}:
  cmd.run:
    - name: 'echo "Screensaver lock-time value is set"'
    - cwd: /root
    {%- else  %}
file_{{ stig_id }}-{{ dconfBanner }}:
  file.replace:
    - name: '{{ dconfBanner }}'
    - pattern: '^\[{{ headerLabel }}\]'
    - repl: |
        {{ dconfHeader }}
        {{ targVal }}
    {%- endif  %}
  {%- else %}
file_{{ stig_id }}-{{ dconfBanner }}:
  file.append:
    - name: '{{ dconfBanner }}'
    - text: |
        {{ dconfHeader }}
        {{ targVal }}
  {%- endif %}
{%- else %}
{%- endif %}
