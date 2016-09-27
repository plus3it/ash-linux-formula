# Finding ID:	RHEL-07-010373
# Version:	RHEL-07-010373_rule
# SRG ID:	SRG-OS-000329-GPOS-00128
# Finding Level:	medium
# 
# Rule Summary:
#	If three unsuccessful root logon attempts within 15 minutes
#	occur the associated account must be locked.
#
# CCI-002238 
#    NIST SP 800-53 Revision 4 :: AC-7 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-010373' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pamFiles = [
                     '/etc/pam.d/system-auth',
                     '/etc/pam.d/password-auth'
                    ]
 %}
{%- set pamMod = 'pam_faillock.so' %}
{%- set lockTO = '900' %}
{%- set authFail = 'auth        [default=die] ' + pamMod + ' authfail deny=3 unlock_time=' + lockTO + ' fail_interval=900 even_deny_root fail_interval=' + lockTO %}
{%- set authSucc = 'auth        required      ' + pamMod + ' authsucc deny=3 unlock_time=' + lockTO + ' fail_interval=900 even_deny_root fail_interval=' + lockTO %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Iterate files to alter...
{%- for checkFile in pamFiles %}
  {%- if salt['file.is_link'](checkFile) %}
      {%- set checkFile = checkFile + '-ac' %}
  {%- endif %}

insert_{{ stig_id }}-{{ checkFile }}_faillock_fail:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^(?P<srctok>auth.*{{ pamMod }}.*authfail.*$)'
    - repl: '\g<srctok> even_deny_root'

insert_{{ stig_id }}-{{ checkFile }}_faillock_succ:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^(?P<srctok>auth.*{{ pamMod }}.*authsucc.*$)'
    - repl: '\g<srctok> even_deny_root'
{%- endfor %}
