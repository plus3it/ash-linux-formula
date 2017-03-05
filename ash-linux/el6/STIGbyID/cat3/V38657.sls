# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38657
# Finding ID:	V-38657
# Version:	RHEL-06-000273
# Finding Level:	Low
#
#     The system must use SMB client signing for connecting to samba
#     servers using mount.cifs. Packet signing can prevent
#     man-in-the-middle attacks which modify SMB packets in transit.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38657' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Ingest list of mounted filesystesm into a searchable-structure
{%- set activeMntStream = salt['mount.active']('extended=true') %}

# Iterate the structure by top-level key
{%- for mountPoint in activeMntStream.keys() %}

# Unpack key values out to searchable dictionary
{%- set mountList = activeMntStream[mountPoint] %}

# Pull fstype value from key-value dictionary
{%- set fsType = mountList['fstype'] %}

# Perform action if mount-type is an SMB/CIFS-type
{%- if fsType == 'smb' or fsType == 'cifs' %}

# Grab the option-list for targeted-mount(s)
{%- set optList = mountList['opts'] %}

  # See if the mount has a client-signing option set
  {%- if 'sec=krb5i' in optList or 'sec=ntlmv2i' in optList or 'sec=ntlmsspi' in optList %}

    # See if using Kerberos v5 client-signing (PASSING CONDITION)
    {%- if 'sec=krb5i' in optList %}
notify_{{ stigId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "CIFS mount {{ mountPoint }} mounted with ''krb5i'' client-signing option"'

    # See if using NTLM v2 client-signing (PASSING CONDITION)
    {%- elif 'sec=ntlmv2i' in optList %}
notify_{{ stigId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "CIFS mount {{ mountPoint }} mounted with ''ntlmv2i'' client-signing option"'

    # See if using NTLM v2 client-signing encapsulated in Raw NTLMSSP message
    # (PASSING CONDITION - STIG only specifically enumerates use of NTLM v2
    # client-signing, but this is an extension to this option)
    {%- elif 'sec=ntlmsspi' in optList %}
notify_{{ stigId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "CIFS mount {{ mountPoint }} mounted with ''ntlmsspi'' client-signing option"'
    {%- endif %}

  # No client-signing in use (FAILURE CONDITION)
  {%- else %}
notify_{{ stigId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'printf "
WARNING: CIFS mount {{ mountPoint }} not mounted with\n
client-signing options.\n
Cannot safely auto-remediate: no way of ensuring that\n
CIFS server supports signed-connections - cannot assure\n
the mount will continue to function if client-side\n
mount-options are altered.\n
MANUAL REMEDIATION REQUIRED.\n"'

##################################################################
## Following sections commented out as it's not safe to attempt
## auto-remediation of CIFS mounts not using client-signing option
##
## # Remount with "sec=krb5i" option added/set
##   {%- set optString = 'sec=krb5i,' + ','.join(optList) %}
##   {%- set remountDev = mountList['alt_device'] %}
## notify_{{ stigId }}-{{ mountPoint }}-remount:
##   cmd.run:
##     - name: 'printf "\t* Attempting remount...\n"'
##
## remount_{{ stigId }}-{{ mountPoint }}:
##   module.run:
##     - name: 'mount.remount'
##     - m_name: '{{ mountPoint }}'
##     - device: '{{ remountDev }}'
##     - fstype: '{{ fsType }}'
##     - opts: '{{ optString }}'
##
##     # Update fstab (if necessary)
##     {%- if salt.file.search('/etc/fstab', '^' + remountDev + '[ 	]') %}
## notify_{{ stigId }}-{{ mountPoint }}-fixFstab:
##   cmd.run:
##     - name: 'printf "\t* Updating /etc/fstab as necessary\n"'
##
## fstab_{{ stigId }}-{{ mountPoint }}:
##   module.run:
##     - name: 'mount.set_fstab'
##     - m_name: '{{ mountPoint }}'
##     - device: '{{ remountDev }}'
##     - fstype: '{{ fsType }}'
##     - opts: '{{ optString }}'
##     {%- endif %}
##################################################################

  {%- endif %}
{%- endif %}
{%- endfor %}
