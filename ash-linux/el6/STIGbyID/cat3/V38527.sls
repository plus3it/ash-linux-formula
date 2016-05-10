# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38527
# Finding ID:	V-38527
# Version:	RHEL-06-000171
# Finding Level:	Low
#
#     The audit system must be configured to audit all attempts to alter 
#     system time through clock_settime. Arbitrary changes to the system 
#     time can be used to obfuscate nefarious activities in log files, as 
#     well as to confuse network services that are highly dependent upon an 
#     accurate system time (such as shd). All changes to the system time
#     should be audited.
#
############################################################
 
{%- set stig_id = '38527' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

{%- if grains['cpuarch'] == 'x86_64' %}
  {%- set pattern = '-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules' %}
  {%- set pattern32 = '-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules' %}
  {%- set filename = '/etc/audit/audit.rules' %}
notify_V{{ stig_id }}-settimeofday:
  cmd.run:
    - name: 'echo "Appropriate audit-rule already present"'
    - onlyif:
      - 'grep -c -E -e "{{ pattern }}" {{ filename }}'

file_V{{ stig_id }}-settimeofday:
  file.append:
    - name: '{{ filename }}'
    - text: |
        
        # Audit all system time-modifications via clock_settime (per STIG-ID V-{{ stig_id }})
        {{ pattern32 }}
        {{ pattern }}
    - unless:
      - 'grep -c -E -e "{{ pattern }}" {{ filename }}'
{%- else %}
file_V{{ stig_id }}-settimeofday:
  cmd.run:
    - name: 'echo "Architecture not supported: no changes made"'
{%- endif %}
