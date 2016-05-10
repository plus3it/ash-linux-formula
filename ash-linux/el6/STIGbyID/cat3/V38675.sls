# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38675
# Finding ID:	V-38675
# Version:	RHEL-06-000308
# Finding Level:	Low
#
#     Process core dumps must be disabled unless needed. A core dump 
#     includes a memory image taken at the time the operating system 
#     terminates an application. The memory image could contain sensitive 
#     data and is generally useful only for developers trying to debug
#     problems.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38675' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set limitsFile = '/etc/security/limits.conf' %}
{%- set limitVal = '0' %}
{%- set searchRoot = '\*[	 ]*hard[	 ]*core' %}
{%- set searchPtn = searchRoot + '[	 ]*' + limitVal + '$' %}
{%- set fixString = '\*	hard	core	' + limitVal %}

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

# If incorrect setting is present, comment it out
badset_{{ stigId }}-noCores:
  file.comment:
    - name: '{{ limitsFile }}'
    - regex: '{{ searchRoot }}[	 ]*[1-9]'
    - onlyif: 'grep -E "^{{ searchRoot }}[ 	]*[1-9]" {{ limitsFile }}'

# Otherwise, add it
set_{{ stigId }}-noCores:
  file.append:
    - name: '{{ limitsFile }}'
    - text: |
        
        # Disable process core dumps (per STIG {{ stigId }})
        *	hard	core	0
    - unless: 'grep -E "{{ searchPtn }}" {{ limitsFile }}'
