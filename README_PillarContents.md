# Guide to Pillar Contents

This project contains a file, [pillar.expample](pillar.example), that's meant to lightly-illustrate the usage of some pillar-variables that can control the execution of this formula. This document will attempt to provider a deeper explanation of _some_ of these pillar variables.


## `ash-linux` 

This is the top-level key in the pillar contents. When executing the `ash-linux-formula` as part of a larger context (e.g. the watchmaker offering that this formula was written to support), this key in the pillar file is this formula's root lookup-token. This token gets added to the larger context's [salt pillar](https://docs.saltproject.io/en/latest/topics/tutorials/pillar.html) and enables the states within this formula to look up content governing its states' execution.

## `lookup`

Next-level pillar-key for this formula's states' governance. Mostly provides a mnemonic entry-pont into the remaining sub-keys.


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
