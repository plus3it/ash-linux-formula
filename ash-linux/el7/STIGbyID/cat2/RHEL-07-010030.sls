# STIG ID:	RHEL-07-010030
# Rule ID:	SV-86483r4_rule
# Vuln ID:	V-71859
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
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pkgName = 'dconf' %}
{%- set dconfDir = '/etc/dconf/db/local.d' %}
{%- set dconfFile = dconfDir + '/01-banner-message' %}
{%- set parmName = 'banner-message-enable' %}
{%- set parmValu = 'true' %}
{%- set headerLabel = 'org/gnome/login-screen' %}
{%- set dconfHeader = '[' + headerLabel + ']' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Handler was selected for skipping...
{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
# The dconf RPM is present
{%- elif salt.pkg.version(pkgName) %}
  # The config file exists
  {%- if salt.file.file_exists(dconfFile) %}
    # The parameter is present and defined
    {%- if salt.file.search(dconfFile, parmName) %}
file_{{ stig_id }}-setVal:
  file.replace:
    - name: '{{ dconfFile }}'
    - pattern: '^[ 	]*{{ parmName }}=.*$'
    - repl: '{{ parmName }}={{ parmValu }}'
    # The parameter is absent but section-header is present
    {%- elif salt.file.search(dconfFile, dconfHeader) %}
file_{{ stig_id }}-setVal:
  file.replace:
    - name: '{{ dconfFile }}'
    - pattern: '^(?P<srctok>\{{ dconfHeader }}.*$)'
    - repl: |-
        \g<srctok>
        {{ parmName }}={{ parmValu }}
    # The parameter and section-header are absent
    {%- else %}
file_{{ stig_id }}-setVal:
  file.append:
    - name: '{{ dconfFile }}'
    - text: |-
        {{ dconfHeader }}
        {{ parmName }}={{ parmValu }}
    {%- endif %}
  # The config file does not exist
  {%- else %}
file_{{ stig_id }}-setVal:
  file.managed:
    - name: '{{ dconfFile }}'
    - user: 'root'
    - contents: |-
        {{ dconfHeader }}
        {{ parmName }}={{ parmValu }}
    - group: 'root'
    - mode: '0644'
  {%- endif %}
# The dconf RPM is not present
{%- else %}
notify_{{ stig_id }}-noRPM:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''RPM {{ pkgName }} not installed: skipping...''\n"'
    - stateful: True
    - cwd: /root
{%- endif %}
