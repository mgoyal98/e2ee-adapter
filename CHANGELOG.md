## [Unreleased]

### Features

* Add enforcement mode support for strict encryption requirements
  * New `enforced` option in E2EEConfig (default: false)
  * When `enforced: true`, strictly requires encryption headers for all requests
  * When `enforced: false`, only processes requests that have encryption headers
  * Supports both Express middleware and NestJS interceptor
  * Useful for gradual migration and production environments

## [0.1.1](https://github.com/mgoyal98/e2ee-adapter/compare/v0.1.0...v0.1.1) (2025-08-03)

### Bug Fixes

* dist folder in github release ([a139935](https://github.com/mgoyal98/e2ee-adapter/commit/a1399353d81b7007c768ab1fd96305c9f26562d4))

## [0.1.0](https://github.com/mgoyal98/e2ee-adapter/compare/v0.0.1...v0.1.0) (2025-08-03)

### Features

* semantic releases ([111acb6](https://github.com/mgoyal98/e2ee-adapter/commit/111acb6725e22e33d602ff6b6f329fe682901c09))
* support for multi keys ([2d80210](https://github.com/mgoyal98/e2ee-adapter/commit/2d80210df0fbcff05f4a6232336e09c1ee2cfd37))
* support for multi keys ([3ead916](https://github.com/mgoyal98/e2ee-adapter/commit/3ead9164ebc05a911663c8bbf75431c104de188f))
