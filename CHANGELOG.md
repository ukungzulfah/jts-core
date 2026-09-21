# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-02-09

### Fixed
- **Incorrect `exp` claim when `expiresIn` is a string (CWE-613 / VAPT-MEDIUM)**:
  `createBearerPass` now coerces `expiresIn` to a finite, non-negative number before
  computing `exp = iat + expiresIn`. Previously a string value (e.g. `"300"` read from an
  environment variable or passed by an untyped JS caller) caused string concatenation,
  producing an `exp` claim far in the future (e.g. `1786690217300` instead of `1786690517`),
  which effectively issued non-expiring tokens. Non-numeric values are now rejected.
- **String lifetimes in `JTSAuthServer` config**: `bearerPassLifetime`, `stateProofLifetime`,
  `gracePeriod`, and `rotationGraceWindow` are coerced to finite numbers on construction,
  fixing the same concatenation issue for the `expiresAt` field returned by `login()`/`renew()`
  when config values arrive as strings.

### Tests
- Added regression tests covering string `expiresIn` (verifies numeric `exp`) and
  rejection of non-numeric `expiresIn`. Suite: 256 → 258 tests, all passing.

## [1.2.0] - 2025-12-02

### Refactored
- **Complete Codebase Restructuring**: Major refactoring for improved maintainability and code organization.
- **Crypto Module**: Extracted `AlgorithmConfig` into separate module for better separation of concerns.
- **Client Module**: Split into dedicated files (`InMemoryTokenStorage.ts`, `types.ts`) for cleaner architecture.
- **Middleware Module**: Extracted constants into `constants.ts` for centralized error code management.

### Improved
- **Code Organization**: Better file structure with single-responsibility modules.
- **Type Safety**: Enhanced TypeScript definitions with dedicated type files.
- **Error Handling**: Centralized JTS error codes and messages in constants.
- **Test Coverage**: All 256 tests passing with comprehensive coverage.

### Technical
- Modular architecture enabling easier maintenance and extension.
- Cleaner imports and exports across the codebase.
- Improved developer experience with better code discoverability.

## [1.1.0] - 2025-12-01

### Added
- **Adapter Development Kit**: New `@engjts/auth/adapter` export for creating custom database adapters.
- **Adapter Documentation**: Comprehensive guides for building database adapters (`docs/ADAPTER_DEVELOPMENT.md`).
- **MySQL Adapter Guide**: Step-by-step guide for creating `@engjts/mysql-adapter` (`docs/CREATE_MYSQL_ADAPTER.md`).
- **AdapterMetadata Interface**: For adapter registration and discovery.

### Changed
- **Dependency Management**: Moved `pg` and `ioredis` from `dependencies` to `peerDependencies` (optional).
  - This allows users to install only the database drivers they need.
  - Reduces package size for projects not using PostgreSQL or Redis.
- **Rollup Configuration**: Added separate build entry for adapter SDK.
- **Package Exports**: New conditional exports for adapter development via `@engjts/auth/adapter`.

### Benefits
- Enable creation of custom adapters for any database (MySQL, MongoDB, SQLite, etc.)
- Maintain backward compatibility with existing PostgreSQL and Redis adapters.
- Reduce bloat by making database drivers optional peer dependencies.
- Support for external adapter packages like `@engjts/mysql-adapter`, `@engjts/mongodb-adapter`, etc.

## [1.0.0] - 2025-12-01

### Changed
- **Release**: Promoted from pre-release `1.0.0-0` to stable `1.0.0`.

## [1.0.0-0] - 2025-12-01

### Changed
- **Migration**: Migrated package from `jts-core` to `@engjts/auth`.
- **Version Reset**: Reset version to `1.0.0-0` to align with the new package scope and release cycle.
- **Documentation**: Updated README and code comments to reflect the new package name.

### Added
- Initial release under `@engjts/auth` scope.
- Includes all features from `jts-core` v1.0.1.
