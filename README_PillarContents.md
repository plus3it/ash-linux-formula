# Guide to Pillar Contents

This project contains a file, [pillar.expample](pillar.example), that's meant to lightly-illustrate the usage of some pillar-variables that can control the execution of this formula. This document will attempt to provider a deeper explanation of _some_ of these pillar variables.


## `ash-linux` 

This is the top-level key in the pillar contents. When executing the `ash-linux-formula` as part of a larger context (e.g. the watchmaker offering that this formula was written to support), this key in the pillar file is this formula's root lookup-token. This token gets added to the larger context's [salt pillar](https://docs.saltproject.io/en/latest/topics/tutorials/pillar.html) and enables the states within this formula to look up content governing its states' execution.

## `lookup`

Next-level pillar-key for this formula's states' governance. Mostly provides a mnemonic entry-pont into the remaining sub-keys.


## `rsyslog`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `cac-enable`

**Status:** _Vestigial_

Currently, no live project-content still references this key. Reference remains in pillar in case content used for earlier Enterprise Linux releases needs to be re-implemented for newer ones.

## `notifier-email`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `skip-stigs`

This pillar-key is a list of state-names. By adding a state-name to this list, the associated state-file's logic will be skipped. The values in this list must exactly match the file-name of an individually-enumerated STIG-finding (minus the file's `.sls` suffix). Typically, this name-value will be something like `RHEL-07-NNNNNN` or `RHEL-08-NNNNNN`. Notionally, any file in this project that contains the code-snippet:

~~~
{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
~~~

Can also be skipped by adding its (suffixless) file-name to this list. However, the baseline assumption is that skippable state-content will almost exclusively be files whose names align to those enumerated in the STIG content published by DISA.

## `mustpatch-days`

**Status:** _Vestigial_

Currently, no live project-content still references this key. Reference remains in pillar in case content used for earlier Enterprise Linux releases needs to be re-implemented for newer ones.

## `home-mode`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `audit-overflow`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `audit-space-action`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `audisp-server`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `audisp-disk-full`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `banned-accts`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `dns-info`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `grub-user`

Explanatory-contents to be added upon request.

## `grub-passwd`

Explanatory-contents to be added upon request.

## `sshd-loglevel`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.

## `scap-profile`

Explanatory-contents to be added upon request.

## `scap-cpe`

Explanatory-contents to be added upon request.

## `scap-ds`

Explanatory-contents to be added upon request.

## `scap-xccdf`

Explanatory-contents to be added upon request.

## `scap-output`

Explanatory-contents to be added upon request.

## `banner`

**Status:** _Vestigial_

Currently, no live project-content still references this key. Reference remains in pillar in case content used for earlier Enterprise Linux releases needs to be re-implemented for newer ones.

## `login-banners`

Explanatory-contents to be added upon request. Currently, only the Enterprise Linux 7 content references this key.
