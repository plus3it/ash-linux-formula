# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38692
# Finding ID:		V-38692
# Version:		RHEL-06-000334
# SCAP Security ID:	CCE-27283-1
# Finding Level:	Low
#
#     Accounts must be locked upon 35 days of inactivity. Disabling 
#     inactive accounts ensures that accounts which may not have been 
#     responsibly removed are not available to attackers who may have 
#     compromised their credentials.
#
#  CCI: CCI-000017
#  NIST SP 800-53 :: AC-2 (3)
#  NIST SP 800-53A :: AC-2 (3).1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-2 (3)
#
############################################################

{%- set stigId = 'V38692' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set checkFile = '/etc/default/useradd' %}
{%- set parmName = 'INACTIVE' %}
{%- set parmVal = '35' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Do nothing if value is already correct
notify_{{ stigId }}-goodVal:
  cmd.run:
    - name: 'echo "Account inactivity-lockout already set to {{ parmVal }} days"'
    - onlyif: 'grep -E "^{{ parmName }}={{ parmVal }}" {{ checkFile }}'

# Uncomment if a commented-out good value is available
uncomment_{{ stigId }}-inactive:
  file.uncomment:
    - name: '{{ checkFile }}'
    - regex: '{{ parmName }}'
    - unless: 'grep -E "^{{ parmName }}={{ parmVal }}" {{ checkFile }}'

# Replace any current bad value
repl_{{ stigId }}-inactive:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^{{ parmName }}=.*$'
    - repl: '{{ parmName }}={{ parmVal }}'
    - unless: 'grep -E "^{{ parmName }}={{ parmVal }}" {{ checkFile }}'

# Add value if none present in other forms
set_{{ stigId }}-inactive:
  file.append:
    - name: '{{ checkFile }}'
    - text: |
        
        # Set {{ parmName }} account-locking (per STIG-ID {{ stigId }})
        {{ parmName }}={{ parmVal }}
    - unless: 'grep -E "^{{ parmName }}={{ parmVal }}" {{ checkFile }}'
