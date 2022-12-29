After hardening has been completed against a OL8 host, the following findings will typically remain when running a further `oscap` report using the `STIG` profile:

* Add noexec Option to /tmp
* Add nosuid Option to /boot
* Configure Multiple DNS Servers in /etc/resolv.conf
* Enable Certmap in SSSD
* Ensure Logs Sent To Remote Host
* Ensure McAfee Endpoint Security for Linux (ENSL) is running
* Ensure Users Re-Authenticate for Privilege Escalation - sudo NOPASSWD
* Install McAfee Endpoint Security for Linux (ENSL)
* Only Authorized Local User Accounts Exist on Operating System
* Set Existing Passwords Maximum Age
* Set Existing Passwords Minimum Age
* Set PAM's Password Hashing Algorithm
* Set PAM's Password Hashing Algorithm - password-auth
* Support session locking with tmux
* Verify Permissions on SSH Server Private *_key Key Files

Of the above findings:
* <i>Add noexec Option to <tt>/tmp</tt></i>: The tested-against EC2s have implemented the `/tmp` filesystem using the `tmp.mount` systemd service. Watchmaker ensures that this option is set in a method aligned to the use of the `tmp.mount` systemd service. The scan *should* be architected to handle this implementation-method but is not.
* <i>Add nosuid Option to <tt>/boot</tt></i>: the tested-against EC2s do not have a standalone `/boot` partition. The scan *should* detect this and not flag the mount-option as missing.
* <i>Configure Multiple DNS Servers</i>: The DNS server value(s) are the result of the deployed-to VPC's DHCP option-set. In normal, CSP-hosted deployments, the EC2 will be pointed to a pool of DNS servers that all answer from a shared, high-availablity IP address
* <i>Enable Certmap in SSSD</i>: Enabling SSSD certmap would typically be a per-site task and would, presumably, be part of the site's use of the [join-domain-formula's](https://github.com/plus3it/join-domain-formula) &ndash; or similar &ndash; activities.
* <i>Ensure Logs Sent To Remote Host</i>: The configuration-test is flawed. It uses EL6-style configuration-method rather than the [method prescribed for EL8](https://access.redhat.com/articles/3549872#clientrhel7).
* <i>Ensure McAfee is running</i>: It is expected that relevant configuration would come by way of the [mcafee-agent-formula](https://github.com/plus3it/mcafee-agent-formula) or similar activities
* <i>Ensure Users Re-Authenticate for Privilege Escalation - sudo NOPASSWD</i>: The default user, if present, is generally configured passwordless and uses SSH key-based logins. Since the account has no password set, the <tt>NOPASSWD</tt> token needs to be set when the provisioning account is present. This test is not generally compatible with cloud-hosted systems.
* <i>Install McAfee Endpoint Security for Linux (ENSL)</i>: It is expected that relevant configuration would come by way of the [mcafee-agent-formula](https://github.com/plus3it/mcafee-agent-formula) or similar activities
* <i>Set Existing Passwords Maximum Age</i>: All (local) users on test-system have locked passwords (not a relevant finding) _and_ are of a type where it would cause lifecycle/maintenance problems if the accounts were configured to expire
* <i>Set Existing Passwords Minimum Age</i>: All (local) users on test-system have locked passwords (not a relevant finding)
* <i>PAM Password Hashing Algorithm</i>:
* <i>PAM Password Hashing Algorithm (password-auth)</i>:
* <i>Support session locking with tmux</i>: Support for session-locking with `tmux` _is_ enabled, however, the scan-test has insufficient logic to properly identify that the configuration-state is valid.
* <i>Verify Permissions on SSH Server Private *_key file-permissions</i>:
