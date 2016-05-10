# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38684
# Rule ID:		accounts_max_concurrent_login_sessions
# Finding ID:		V-38684
# Version:		RHEL-06-000319
# SCAP Security ID:	CCE-27457-1
# Finding Level:	Low
#
#     The system must limit users to 10 simultaneous system logins, or a 
#     site-defined number, in accordance with operational requirements. 
#     Limiting simultaneous user logins can insulate the system from denial 
#     of service problems caused by excessive logins. Automated login 
#     processes operating improperly or maliciously may result in an 
#     exceptional number of simultaneous login sessions.
#
#  CCI: CCI-000054
#  NIST SP 800-53 :: AC-10
#  NIST SP 800-53A :: AC-10.1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-10
#
############################################################

{%- set stigId = 'V38684' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set limitsFile = '/etc/security/limits.conf' %}
{%- set limitVal = '10' %}
{%- set searchRoot = '\*[	 ]*hard[	 ]*maxlogins' %}
{%- set searchPtn = searchRoot + '[	 ]*' + limitVal + '$' %}
{%- set fixString = '*	hard	maxlogins	' + limitVal %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# If correct setting is present but commented, uncomment it
uncomment_{{ stigId }}-noCores:
  file.uncomment:
    - name: '{{ limitsFile }}'
    - regex: '{{ searchPtn }}'
    - onlyif: 'grep -E "#*{{ searchPtn }}" {{ limitsFile }}'

# Otherwise, add it
set_{{ stigId }}-noCores:
  file.append:
    - name: '{{ limitsFile }}'
    - text: |
        
        # Disable process core dumps (per STIG {{ stigId }})
        {{ fixString }}
    - unless: 'grep -E "{{ searchPtn }}" {{ limitsFile }}'
