# Security

This tool handles TLS client certificates and credentials for connecting
to TAK servers, and by design sits at the trust boundary between
independently-administered networks (see the README's discussion of
what that means for who can see what). Treat it accordingly:

- Don't expose the web panel to the open internet without `RELAY_WEB_TLS=1`
  and a panel login configured (see README - "Panel access", "Encrypting
  the panel itself").
- Review who has access to the machine running the relay - it holds
  private keys for every server it's configured to connect to.

## Reporting a vulnerability

Please open a GitHub issue for non-sensitive reports, or reach out
privately (see the profile on this repository) for anything that
shouldn't be public before a fix is available. This is maintained
alongside other work, so response time isn't guaranteed, but security
reports get priority over feature requests.
