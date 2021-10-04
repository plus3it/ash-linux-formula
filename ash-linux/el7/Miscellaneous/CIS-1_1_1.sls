# Rule Name:    sshd_set_loglevel_info
# CIS Rule ID:  1.1.1
#
# Rule Summary:
#	Disable non-standard or non-native filesystem-types:
#
#   A number of uncommon filesystem types are supported under
#   Linux. Removing support for unneeded filesystem types
#   reduces the local attack surface of the system. If a
#   filesystem type is not needed it should be disabled. Native
#   Linux file systems are designed to ensure that built-in
#   security controls function as expected. Non-native
#   filesystems can lead to unexpected consequences to both the
#   security and functionality of the system and should be used
#   with caution. Many filesystems are created for niche use
#   cases and are not maintained and supported as the operating
#   systems are updated and patched. Users of non-native
#   filesystems should ensure that there is attention and
#   ongoing support for them, especially in light of frequent
#   operating system changes.
#
#   Standard network connectivity and Internet access to cloud
#   storage may make the use of non-standard filesystem formats
#   to directly attach heterogeneous devices much less
#   attractive
#
#################################################################
{%- set stig_id = 'CIS-1.1.1' %}
{%- set helperLoc = 'Miscellaneous/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/modprobe.d/CIS-1.1.1.conf %}
{%- set mediaFStypes = [
                        'cramfs',
                        'freevxfs',
                        'jffs2',
                        'hfs',
                        'hfsplus',
                        'squashfs'
                         ] %}

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
  {%- for mediaFStype in mediaFStypes %}
blacklist_{{ stig_id }}-{{ mediaFStype }}:
  file.append:
    - name: '{{ cfgFile }}'
    - text:
      - install {{ mediaFStype }} /bin/true
    - makedirs: true
  {%- endfor %}
{%- endif %}
