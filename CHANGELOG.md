# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-14

### Changed

- Removed the `Wrote N cookie(s) to <path>` stderr message printed after writing to `--output`.
  It was just noise and the cookie file already tells you how many cookies were written.
