# Governance

Harnis was started by **Ahmad Karawash** and is provided **"as is"** under the [Apache License 2.0](LICENSE), without warranty or support of any kind. You are free to use, change, fork and redistribute it under the terms of that license.

## Decisions

The maintainers decide what is merged and released, at their own discretion. There is no commitment to review or merge contributions, answer issues, publish releases or keep any interface stable.

## Versions

Releases use [Semantic Versioning](https://semver.org/) numbers as an indication of the kind of change (patch: fixes; minor: new features; major: breaking changes), on a best-effort basis. Read [CHANGELOG.md](CHANGELOG.md) before upgrading, test upgrades in your own environment, and run `python -m harnis.migrate` after installing a new version.

## Your responsibilities when using Harnis

* **Operation and security.** You are responsible for how you deploy, configure, secure and operate Harnis, and for the actions agents take in your environment.
* **Third-party licenses.** Harnis depends on third-party packages, container images, models and services, each under its own license or terms. You are responsible for reviewing them and obtaining any licenses you need.
* **Data and compliance.** You are responsible for the data you send to model providers and for meeting your legal and contractual obligations.
