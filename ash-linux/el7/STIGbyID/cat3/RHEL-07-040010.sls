# STIG URL:
# Finding ID:	RHEL-07-040010
# Version:	RHEL-07-040010_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The operating system must limit the number of concurrent 
#     sessions to ten for all accounts and/or account types.
#
# CCI-000054
#    NIST SP 800-53 :: AC-10
#    NIST SP 800-53A :: AC-10.1 (ii)
#    NIST SP 800-53 Revision 4 :: AC-10
#
#################################################################
{%- set stig_id = 'RHEL-07-040010' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set limitsFile = '/etc/security/limits.conf' %}
{%- set limitVal = '10' %}
{%- set searchRoot = '\*[	 ]*hard[	 ]*maxlogins' %}
{%- set searchPtn = searchRoot + '[	 ]*' + limitVal + '$' %}
{%- set fixString = '*	hard	maxlogins	' + limitVal %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# If correct setting is present but commented, uncomment it
uncomment_{{ stig_id }}-maxlogins:
  file.uncomment:
    - name: '{{ limitsFile }}'
    - regex: '{{ searchPtn }}'
    - onlyif: 'grep -E "#*{{ searchPtn }}" {{ limitsFile }}'

# Otherwise, add it
set_{{ stig_id }}-maxlogins:
  file.append:
    - name: '{{ limitsFile }}'
    - text: |
        
        # Limit concurrent login sessions (per STIG {{ stig_id }})
        {{ fixString }}
    - unless: 'grep -E "{{ searchPtn }}" {{ limitsFile }}'
