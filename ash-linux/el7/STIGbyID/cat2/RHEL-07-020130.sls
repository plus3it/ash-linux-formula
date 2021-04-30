# Finding ID:	RHEL-07-020130
# Version:	RHEL-07-020130_rule
# SRG ID:	SRG-OS-000363-GPOS-00150
# Finding Level:	medium
#
# Rule Summary:
#	A file integrity tool must verify the baseline operating system
#	configuration at least weekly.
#
# CCI-001744
#    NIST SP 800-53 Revision 4 :: CM-3 (5)
#
#################################################################
{%- set stig_id = 'RHEL-07-020130' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set hostname = salt.grains.get('fqdn') %}
{%- set ntfyMail = salt.pillar.get('ash-linux:lookup:notifier-email', 'root') %}
{%- set foundCrons = [] %}
{%- set cronFiles = [] %}
{%- if salt.file.file_exists('/var/spool/cron/root') %}
  {%- do cronFiles.append('/var/spool/cron/root') %}
{%- endif %}
{%- set cronDirs = [
                     '/etc/cron.daily',
                     '/etc/cron.hourly',
                     '/etc/cron.monthly',
                     '/etc/cron.weekly'
                   ] %}
{%- for cronDir in cronDirs %}
  {%- do cronFiles.extend(salt.file.find(cronDir, maxdepth=1, type='f')) %}
{%- endfor %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
  {%- if salt.pkg.version('aide') %}
    {%- for cronFile in cronFiles %}
      {%- if salt.file.search(cronFile, '/aide ') %}
        {%- do foundCrons.append(cronFile) %}
      {%- endif %}
    {%- endfor %}

    {%- if foundCrons %}
notify_{{ stig_id }}-aideFound:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found cron entries for AIDE.''\n"'
    - cwd: /root
    - stateful: True
    {%- else %}
notify_{{ stig_id }}-aideFound:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found no cron entries for AIDE: fixing...''\n"'
    - cwd: /root
    - stateful: True

cron_{{ stig_id }}-file:
  file.append:
    - name: /var/spool/cron/root
    - text: |-
        0 0 * * * /usr/sbin/aide --check | /bin/mail -s "aide integrity check run for {{ hostname }}" {{ ntfyMail }}

cron_{{ stig_id }}-service:
  service.running:
    - name: 'crond.service'
    - watch:
      - file: cron_{{ stig_id }}-file

    {%- endif %}
  {%- else %}
notify_{{ stig_id }}-aideFound:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''AIDE subsystem not installed.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
