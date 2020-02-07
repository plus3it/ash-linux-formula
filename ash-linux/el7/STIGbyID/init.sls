include:
  - ash-linux.el7.STIGbyID.cat1.RHEL-07-021350
  - ash-linux.el7.STIGbyID.cat1.RHEL-07-010482
  - ash-linux.el7.STIGbyID.cat2.RHEL-07-040110
  - ash-linux.el7.STIGbyID.cat2.RHEL-07-040350
  - ash-linux.el7.STIGbyID.cat2.RHEL-07-040400
  - ash-linux.el7.STIGbyID.cat2.RHEL-07-021620



Print ash-linux el7 stig baseline help:
  test.show_notification:
    - text: |
        The full, item-by-item `ash-linux.stig` baseline for EL7 is in beta. 
        This stub will only manage FIPS mode, the GRUB password and the SSH
        daemon's IgnoreRhosts setting on the system.
        
        To apply the full beta STIG, please use the state: `ash-linux.el7.stig`
