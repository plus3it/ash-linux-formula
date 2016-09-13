# Finding ID:	RHEL-07-010030
# Version:	RHEL-07-010030_rule
# SRG ID:	SRG-OS-000023-GPOS-00006
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must display the Standard Mandatory DoD
#	Notice and Consent Banner before granting local or remote
#	access to the system via a graphical user logon.
#
# CCI-000048 
#    NIST SP 800-53 :: AC-8 a 
#    NIST SP 800-53A :: AC-8.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-8 a 
#
#################################################################
{%- set stig_id = 'RHEL-07-010030' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pkgName = 'dconf' %}
{%- set dconfDir = '/etc/dconf/db/local.d' %}
{%- set targVal = 'banner-message-enable=true' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt['pkg.version'](pkgName) %}
{%- set dconfFiles = salt['file.find'](dconfDir, type='f') %}
  {%- if dconfFiles %}
    {%- for dconfFile in dconfFiles %}
      {%- if salt['file.search'](dconfFile, '^' + targVal + '$') %}
file_{{ stig_id }}-{{ dconfFile }}:
  cmd.run:
    - name: 'echo "Banner value set in {{ dconfFile }}"'
    - cwd: /root
      {%- else %}
file_{{ stig_id }}-{{ dconfFile }}:
  cmd.run:
    - name: 'echo "Banner value not set in {{ dconfFile }}"'
    - cwd: /root
      {%- endif %}
    {%- endfor %}
  {%- else %}
file_{{ stig_id }}-setVal:
  file.append:
    - name: '{{ dconfDir }}/01-banner-message'
    - text: |
        [org/gnome/login-screen] 
        {{ targVal }}
    - makedirs: true
  {%- endif %}
{%- else %}
file_{{ stig_id }}-setVal:
  cmd.run:
    - name: 'echo "Package ''{{ pkgName }}'' not installed: state not applicable."'
    - cwd: /root
{%- endif %}
