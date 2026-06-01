# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `:finch_pools` config option, passed through as Finch's `:pools` option, to allow configuring the `GQL.Finch` pool (e.g. TLS transport options).
- `GQL.lenient_eku_transport_opts/1` helper to work around OTP's strict extended key usage validation (CVE-2024-53846) while keeping full TLS peer verification.

## [0.6.2] - 2023-03-11
### Changed
- Relax `nimble_options` version requirement
