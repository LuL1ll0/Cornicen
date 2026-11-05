# Security policy

## Supported versions

Only the latest version on `main` gets security fixes. Cornicen is pre-1.0, so there are no maintained older branches.

## Reporting a vulnerability

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Please don't open a public issue for a vulnerability.

Include the version, what you did, what happened and what you expected. Use a fictional watch list in any reproduction, never your real inventory.

## Scope

In scope: the Cornicen code and container in this repository, including how it fetches and parses the CVE List, KEV and EPSS, how it stores data, and how it sends notifications.

Out of scope: vulnerabilities in the products Cornicen alerts you about (report those to their vendor), errors in the upstream data (report those to the CNA, CISA or FIRST), and your ntfy server.
