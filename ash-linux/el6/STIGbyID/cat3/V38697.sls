# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38697
# Finding ID:	V-38697
# Version:	RHEL-06-000336
# Finding Level:	Low
#
#     Failing to set the sticky bit on public directories allows 
#     unauthorized users to delete files in the directory structure. The 
#     only authorized public directories are those temporary directories 
#     supplied with the system, or those designed to be temporary file 
#     repositories. The setting is normally reserved for directories used 
#     by the system, and by users for temporary file storage - such as /tmp 
#     - and for directories requiring global read/write access. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38697' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# STIG specifies a fix for an indeterminate list. The following only 
# addresses the Linux default directories /tmp, /var/tmp and /dev/shm.
# Prior STIGS require looking for other objects with overly-generous
# permissions and resetting them. Will explore appropriate resetting
# permissions against an indeterminite directory-list in future
# iterations of this SLS.

{%- set dirTmp = '/tmp' %}
{%- set dirVarTmp = '/var/tmp' %}

{%- if salt.file.check_perms(dirTmp, '', 'root', 'root', '1777') %}
directory_{{ stigId }}-tmp:
  cmd.run:
    - name: 'echo "The ''{{ dirTmp }}'' directory already set to mode 1777"'
{%- else %}
directory_{{ stigId }}-tmp:
  file.directory:
    - name: {{ dirTmp }}
    - mode: 1777
{%- endif %}

{%- if salt.file.check_perms(dirVarTmp, '', 'root', 'root', '1777') %}
directory_{{ stigId }}-varTmp:
  cmd.run:
    - name: 'echo "The ''{{ dirVarTmp }}'' directory already set to mode 1777"'
{%- else %}
directory_{{ stigId }}-varTmp:
  file.directory:
    - name: {{ dirVarTmp }}
    - mode: 1777
{%- endif %}
