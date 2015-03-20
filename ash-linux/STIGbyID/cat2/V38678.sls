# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38678
# Finding ID:	V-38678
# Version:	RHEL-06-000311
# Finding Level:	Medium
#
#     The audit system must provide a warning when allocated audit record 
#     storage volume reaches a documented percentage of maximum audit 
#     record storage capacity. Notifying administrators of an impending 
#     disk space problem may allow them to take corrective action prior to 
#     any disruption.
#
#  CCI: CCI-000143
#  NIST SP 800-53 :: AU-5 (1)
#  NIST SP 800-53A :: AU-5 (1).1 (ii)
#
############################################################

script_V38678-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38678.sh
    - cwd: '/root'

{%- set auditConf = '/etc/audit/auditd.conf' %}
{%- set logParm = 'space_left' %}
{%- set auditDir = '/var/log/audit' %}
{%- set pctFree = '0.15'|float %}

# Ingest statvfs data for auditDir into unpackable structure
{%- set auditInfoStream = salt['status.diskusage'](auditDir) %}

# Unpack key-values out to searchable dictionary
{%- set auditDict = auditInfoStream[auditDir] %}

# Get max-size of auditDir
{%- set auditDiskTotBlocks = auditDict['total'] %}

# Compute MB to reserve
{%- set keepFreeMB = ((auditDiskTotBlocks * pctFree) / 1024 / 1024)|int %}
{%- set keepFreeVar = keepFreeMB|string %}


{%- if salt['file.search'](auditConf, '^' + logParm + ' = ') %}
  {%- if salt['file.search'](auditConf, '^' + logParm + ' = ' + keepFreeVar) %}
notify_V38678-Set:
  cmd.run:
    - name: 'echo "''{{ logParm }}'' value in ''{{ auditConf }}'' already set to {{ pctFree }} of free blocks [{{ keepFreeMB }}MB]"'
  {%- else %}
notify_V38678-Set:
  cmd.run:
    - name: 'echo "Changing ''{{ logParm }}'' value in ''{{ auditConf }}'' to {{ pctFree }} of free blocks [{{ keepFreeMB }}MB]"'

file_V38678-setVal:
  file.replace:
    - name: '{{ auditConf }}'
    - pattern: '^{{ logParm }} = .*'
    - repl: '{{ logParm }} = {{ keepFreeVar }}'
  {%- endif %}

{%- else %}
notify_V38678-Set:
  cmd.run:
    - name: 'echo "''{{ logParm }}'' not set in ''{{ auditConf }}''. Setting to {{ pctFree }} of free blocks [{{ keepFreeMB }}MB]"'

file_V38678-setVal:
  file.append:
    - name: '{{ auditConf }}'
    - text: '{{ logParm }} = {{ keepFreeVar }}'
{%- endif %}
