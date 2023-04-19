<!--suppress HtmlDeprecatedAttribute -->
<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
  <br>EBSI Legal Entity DID provider
  <br>
</h1>

**NOTE:**
Currently this plugin only creates a DID Document and stores the key in the KMS. It has no support for the RPC methods
of the DID registry yet. As such this module probably is of little use in the current state for most people.

This plugin supports EBSI v1 (Legal Entity) DID creation. Please note that for Natural Persons on EBSI you should use
our [did:key](../did-provider-key) plugin. This provider dos not support EBSI v2. Please be aware that v2 is not an
upgrade! v2 was an interim and now defunct DID method for Natural Persons. EBSI v1 is for Legal Entities and did:key is
for Natural
Persons. As a consequence we decided not to implement the v2 version.
