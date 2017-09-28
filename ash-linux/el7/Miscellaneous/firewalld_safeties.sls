# Summary:
#
#    This state acts as a safety-valve for hardening-actions that 
#    result in the firewalld zone being changed from 'public' to 
#    something more-restrictive (typically 'drop'). This state 
#    ensures that the firewalld service allows establishment of 
#    SSH-based connections and continuence of existing connections 
#    after a firewalld zone-change action.
#
#################################################################

firewalld_file-safeties:
  cmd.run:
    - name: |
        firewall-offline-cmd --direct --add-rule ipv4 filter INPUT_direct 10 -m state --state RELATED,ESTABLISHED -m comment --comment 'Allow related and established connections' -j ACCEPT > /dev/null 2>&1
        firewall-offline-cmd --direct --add-rule ipv4 filter INPUT_direct 20 -i lo -j ACCEPT > /dev/null 2>&1
        firewall-offline-cmd --direct --add-rule ipv4 filter INPUT_direct 30 -d 127.0.0.0/8 '!' -i lo -j DROP > /dev/null 2>&1
        firewall-offline-cmd --direct --add-rule ipv4 filter INPUT_direct 50 -p tcp -m tcp --dport 22 -j ACCEPT > /dev/null 2>&1
        systemctl reload firewalld
