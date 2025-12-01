# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
