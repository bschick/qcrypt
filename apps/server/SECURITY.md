## Quick Crypt Security

[Quick Crypt](https://quickcrypt.org) is designed to protect your private data, so we naturally take security very seriously and welcome peer reviews and vulnerability reporting. Quick Crypt maintains a bug bounty program at [Open Bug Bounty](https://www.openbugbounty.org/bugbounty/schickb/)

### Reporting

Please use our [vulnerability disclosure program at Open Bug Bounty](https://www.openbugbounty.org/bugbounty/schickb/) to provide details and repro steps. We will respond ASAP. If you cannot use Open Bug Bounty, you may [open a ticket on github](https://github.com/bschick/qcrypt/issues/new/choose) with details and repro steps.

### Rewards (sorry but fees, taxes, etc come out of these amounts)
- up to $50 for low to medium severity findings
- $100 for high severity findings
- $200 for critical findings
- determination of severity will be a discussion, but quickcrypt.org is the final decision-maker
- paid via Paypal, Venmo, or USDC
- if desired, your information and finding will be added to Acknowledgments in this file

### Requirements for submission
- focus on leaks of user credential information and errors in the core encryption decryption protocol
- do not perform DoS or any form of load testing 
- do not send social engineering exploits
- source code scanning is encouraged, but please filter out AI generated noise before submission
    - https://github.com/bschick/qcrypt
    - https://github.com/bschick/qcrypt-server
- always send a working PoC and explain the problem clearly
- attach screenshots or API response data to demonstrate issues
- sending a remediation is appreciated but not required
- highlight the problem in source code whenever possible
- private submissions preferred, but public and private are accepted
- review the [detailed description of Quick Crypt's encryption and decryption protocol](https://quickcrypt.org/help/protocol)
