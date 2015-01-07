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

script_V38657-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38657.sh

# Need to ID fstab-managed CIFS mounts then examine any hits
{% if salt['file.search']('/etc/fstab', 'cifs') %}
notify_V38657-notImp:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'
{% else %}
notify_V38657-noCIFS:
  cmd.run:
  - name: 'echo "No relevant finding: no CIFS mounts managed within /etc/fstab"'
{% endif %}

# Will want to check /etc/mtab and autofs configs, as well...

# Ingest list of mounted filesystesm into a searchable-structure
{% set activeMntStream = salt['mount.active']('extended=true') %}

# Iterate the structure by top-level key
{% for mountPoint in activeMntStream.keys() %}

# Unpack key values out to searchable dictionary
{% set mountList = activeMntStream[mountPoint] %}

# Pull fstype value from key-value dictionary
{% set fsType = mountList['fstype'] %}

# Perform action if mount-type is an SMB/CIFS-type
{% if fsType == 'smb' or fsType == 'cifs' %}

# Grab the option-list for mount
{% set optList = mountList['opts'] %}
  # See if the mount has a client-signing option set
  {% if 'sec=krb5i' in optList or 'sec=ntlmv2i' in optList or 'sec=ntlmsspi' in optList %}
    # See if using Kerberos v5 client-signing (PASSING CONDITION)
    {% if 'sec=krb5i' in optList %}
notify_V38652-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "CIFS mount {{ mountPoint }} mounted with ''krb5i'' client-signing option"'
    # See if using NTLM v2 client-signing (PASSING CONDITION)
    {% elif 'sec=ntlmv2i' in optList %}
notify_V38652-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "CIFS mount {{ mountPoint }} mounted with ''ntlmv2i'' client-signing option"'
    {% elif 'sec=ntlmsspi' in optList %}
notify_V38652-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "CIFS mount {{ mountPoint }} mounted with ''ntlmsspi'' client-signing option"'
    {% endif %}
  {% else %}
notify_V38652-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "CIFS mount {{ mountPoint }} not mounted with client-signing options:"'

## # Remount with "sec=krb5i" option added/set
##   {% set optString = 'sec=krb5i,' + ','.join(optList) %}
##   {% set remountDev = mountList['alt_device'] %}
## notify_V38652-{{ mountPoint }}-remount:
##   cmd.run:
##   - name: 'printf "\t* Attempting remount...\n"'

## remount_V38652-{{ mountPoint }}:
##   module.run:
##   - name: 'mount.remount'
##   - m_name: '{{ mountPoint }}'
##   - device: '{{ remountDev }}'
##   - fstype: '{{ fsType }}'
##   - opts: '{{ optString }}'

##     # Update fstab (if necessary)
##     {% if salt['file.search']('/etc/fstab', '^' + remountDev + '[ 	]') %}
## notify_V38652-{{ mountPoint }}-fixFstab:
##   cmd.run:
##   - name: 'printf "\t* Updating /etc/fstab as necessary\n"'
## 
## fstab_V38652-{{ mountPoint }}:
##   module.run:
##   - name: 'mount.set_fstab'
##   - m_name: '{{ mountPoint }}'
##   - device: '{{ remountDev }}'
##   - fstype: '{{ fsType }}'
##   - opts: '{{ optString }}'
##     {% endif %}

  {% endif %}
{% endif %} 
{% endfor %}
