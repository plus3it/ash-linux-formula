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
{%- set hostname = salt.grains.get('fqdn') %}
{%- set ntfyMail = salt.pillar.get('ash-linux:lookup:notifier-email', 'root') %}
{%- set foundCrons = [] %}
{%- set cronFiles = [ '/var/spool/cron/root' ] %}
{%- set cronDirs = [
                     '/etc/cron.daily',
                     '/etc/cron.hourly',
                     '/etc/cron.monthly',
                     '/etc/cron.weekly'
                   ] %}
{%- for cronDir in cronDirs %}
  {%- do cronFiles.extend(salt.file.find(cronDir, maxdepth='0', type='f')) %}
{%- endfor %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt.pkg.version('aide') %} 
  {%- for cronFile in cronFiles %}
    {%- if salt.file.search(cronFile, '/aide ') %}
      {%- do foundCrons.append(cronFile) %}
    {%- endif %}
  {%- endfor %}

  {%- if foundCrons %}
notify_{{ stig_id }}-aideFound:
  cmd.run:
    - name: 'echo "Found cron entries for AIDE"'
    - cwd: /root
  {%- else %}
notify_{{ stig_id }}-aideFound:
  cmd.run:
    - name: 'echo "Found no cron entries for AIDE: fixing..."'
    - cwd: /root

cron_{{ stig_id }}-file:
  file.append:
    - name: /var/spool/cron/root
    - text: |
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
    - name: 'echo "AIDE subsystem not installed"'
    - cwd: /root
{%- endif %}
