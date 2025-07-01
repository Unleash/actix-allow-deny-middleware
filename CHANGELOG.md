# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/Unleash/actix-allow-deny-middleware/compare/v0.1.1...v0.1.2) - 2025-07-01

### 💼 Other
- Add test to confirm ports > 32768 works ([#8](https://github.com/unleash/actix-allow-deny-middleware/issues/8)) (by @chriswk) - #8

### Dependency updates
- bump actix-service from 2.0.2 to 2.0.3 ([#2](https://github.com/unleash/actix-allow-deny-middleware/issues/2)) (by @dependabot[bot]) - #2
- bump actions/create-github-app-token from 1 to 2 ([#5](https://github.com/unleash/actix-allow-deny-middleware/issues/5)) (by @dependabot[bot]) - #5
- bump actix-web from 4.9.0 to 4.11.0 ([#7](https://github.com/unleash/actix-allow-deny-middleware/issues/7)) (by @dependabot[bot]) - #7

### Contributors

* @dependabot[bot]
* @chriswk

## [0.1.1](https://github.com/Unleash/actix-allow-deny-middleware/compare/v0.1.0...v0.1.1) - 2025-03-03

### 🐛 Bug Fixes
- deny middleware only denies if it has ip and entries in deny list (by @chriswk)

### Contributors

* @chriswk

## [0.1.0](https://github.com/Unleash/actix-allow-deny-middleware/releases/tag/v0.1.0) - 2025-02-28

### 🚀 Features
- added allow and deny middlewares (by @chriswk)
- Make it easy to build Allow and Disallow middlewares from single ips or lists of ips (by @chriswk)
- added allow and disallow list middlewares (by @chriswk)

### 💼 Other
- Setup CI + release-plz (by @chriswk)
- initial commit (by @chriswk)

### ⚙️ Miscellaneous Tasks
- *(ci)* setup semver check for releases (by @chriswk)
- *(release)* Added changelog file (by @chriswk)
- transfer license to Bricks Software (by @chriswk)
- *(ci)* update release-plz with new crate name (by @chriswk)
- added tests for allow middleware (by @chriswk)
- *(ci)* Setup release-plz (by @chriswk)
- *(clippy)* thanks (by @chriswk)
- added dependabot and mergify setup (by @chriswk)

### Contributors

* @chriswk
