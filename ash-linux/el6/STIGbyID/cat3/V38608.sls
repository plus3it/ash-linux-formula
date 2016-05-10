# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38608
# Finding ID:	V-38608
# Version:	RHEL-06-000230
# Finding Level:	Low
#
#     The SSH daemon must set a timeout interval on idle sessions. Causing 
#     idle users to be automatically logged out guards against compromises 
#     one system leading trivially to compromises on another.
#
#  CCI: CCI-001133
#  NIST SP 800-53 :: SC-10
#  NIST SP 800-53A :: SC-10.1 (ii)
#  NIST SP 800-53 Revision 4 :: SC-10
#
############################################################

{%- set stigId = 'V38608' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'ClientAliveInterval' %}
{%- set parmVal = '900' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root
  
# Comment out existing defines if they're wrong
file_{{ stigId }}-comment:
  file.comment:
    - name: '{{ cfgFile }}'
    - regex: '^{{ parmName }}'
    - unless: 'grep -E "^{{ parmName }}" {{ cfgFile }} && grep -E "^{{ parmName }} {{ parmVal }}" {{ cfgFile }}'

# Add ClientAliveInterval setting if valid value not present
file_{{ stigId }}-configSet:
  file.append:
    - name: '{{ cfgFile }}'
    - text: |
        
        # SSH service must set a session idle-timeout (per STIG V-38608)
        {{ parmName }} {{ parmVal }}
    - unless: 'grep -E "^{{ parmName }} {{ parmVal }}" {{ cfgFile }}'

# Restart service if there's been changes to sshd_config
svc_{{ stigId }}-configChk:
  service:
    - name: sshd
    - running
    - watch:
      - file: '{{ cfgFile }}'
