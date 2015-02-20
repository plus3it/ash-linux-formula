# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - sysctl_fs_suid_dumpable
#
# Security identifiers:
# - CCE-27044-7.sls
#
# Rule Summary: Disable core dumps for SUID programs
#
# Rule Text: The core dump of a setuid program is more likely to contain 
#            sensitive data, as the program itself runs with greater 
#            privileges than the user who initiated execution of the 
#            program. Disabling the ability for any setuid program to 
#            write a core file decreases the risk of unauthorized access 
#            of such data.
#
#################################################################

{%- set helperLoc = 'ash-linux/SCAPonly/low/files' %}
{%- set scapId = 'CCE-27044-7' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'fs.suid_dumpable' %}
{%- set notify_change = '''{{ parmName }}'' value set to ''0''' %}
{%- set notify_nochange = '''{{ parmName }}'' value already set to ''0''' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'


#####################################################################
# Later EL6 are secure-by-default. However, many security tools
# don't care about "secure-by-default" settings, So we need to
# ensure that the config file contains the expected setting-string.
#

# Ensure file {{ checkFile }} exists
{%- if salt['file.file_exists'](checkFile) %}

TEST-{{ scapId }}:
  cmd.run:
    - name: 'echo "{{ checkFile }} exists"'

  # See if *a* value is set in {{ checkFile }}
  {%- if salt['file.search'](checkFile, parmName) %}
    # See if *correct* value is set in {{ checkFile }}
    {%- if salt['file.search'](checkFile, '^' + parmName + ' = 0') %}

notify_{{ scapId }}-{{ param_name }}:
  cmd.run:
    - name: 'echo "{{ notify_nochange }}"'

    {%- else %}

notify_{{ scapId }}-{{ param_name }}:
  cmd.run:
    - name: 'echo "{{ notify_change }}"'

# OVERRIDE CURRENT VALUE

    {%- endif %}

  {%- else %}

notify_{{ scapId }}-{{ param_name }}:
  cmd.run:
    - name: 'echo "{{ parmName }} does not exist in {{ checkFile }}"'

append_{{ scapId }}-{{ parmName }}:
  file.append:
    - name: '{{ checkFile }}'
    - text: |
        # Explicitly setting {{ parmName }} per SCAP-ID: {{ scapId }}
        {{ parmName }} = 0

  {%- endif %}

# This should *NEVER* match
{%- else %}

touch__{{ scapId }}-{{ checkFile }}:
  file.managed:
    - name: '{{ checkFile }}'
    - mode: '0600'
    - user: 'root'
    - group: 'root'

append_{{ scapId }}-{{ parmName }}:
  file.append:
    - name: '{{ checkFile }}'
    - text: |
        # Explicitly setting {{ parmName }} per SCAP-ID: {{ scapId }}
        {{ parmName }} = 0
    - unless: 'touch__{{ scapId }}-{{ checkFile }}'

{%- endif %}

#
#####################################################################


#####################################################################
# Handle run-time/in-memory verification or setting of {{ parmName }}

# Might want to use sysctl.present to do this and replace all of the above
setting_{{ scapId }}-{{ parmName }}:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '0'
#
#####################################################################

