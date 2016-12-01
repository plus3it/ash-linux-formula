# Finding ID:	RHEL-07-040300
# Version:	RHEL-07-040300_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	The system must display the date and time of the last successful account logon upon logon.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040300' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/pam.d/postlogin'%}
{%- set headerStr = 'User changes will be destroyed the next time authconfig is run' %}
{%- set insertStr = 'session	required	pam_lastlog.so showfailed' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
{%- else %}
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^(?P<srctok>#.*{{ headerStr }}.*$)'
    - repl: |-
        \g<srctok>

        # Inserted per STIG {{ stig_id }}
        {{ insertStr }}
    - unless: 'grep -q "{{ insertStr }}" {{ cfgFile }}'
        
{%- endif %}
