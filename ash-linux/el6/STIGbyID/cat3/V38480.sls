# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38480
# Finding ID:	V-38480
# Version:	RHEL-06-000054
# Finding Level:	Low
#
#     Users must be warned 7 days in advance of password expiration. 
#     Setting the password warning age enables users to make the change at 
#     a practical time.
#
############################################################

{%- set stigId = 'V38480' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Super-ugly: gotta spiff later
script_{{ stigId }}-helper:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}-helper.sh
    - cwd: /root
