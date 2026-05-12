<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->
# agent.md — Codebase Guide for AI Agents

This document provides structured guidance for AI coding agents working on the **Team Folders** (`groupfolders`) Nextcloud app.

---

## Project Overview

**Team Folders** (app ID: `groupfolders`) is a Nextcloud app that allows admins to create shared folders accessible to groups, users, or Teams (Circles). Key features include:

- Admin-managed shared folders for groups/teams
- Configurable per-folder storage quotas
- Advanced ACL-based permissions (per-file/folder, per-user/group)
- Trash and versioning integration
- Key-value tag system for Team folders
- OCC CLI commands for full management
- REST + WebDAV APIs

**Current version:** `22.0.0` (see `appinfo/info.xml`)  
**Nextcloud compatibility:** 34

---

## Directory Structure

```
groupfolders/
├── appinfo/
│   └── info.xml              # App metadata, commands, background jobs, dependencies
├── lib/
│   ├── ACL/                  # Advanced permissions (ACLManager, RuleManager, ACLCacheWrapper)
│   ├── AppInfo/              # App registration and DI wiring
│   ├── BackgroundJob/        # Cron jobs (expire versions, expire trash)
│   ├── Command/              # OCC CLI commands
│   │   └── Tag/              # Tag-management commands (SetTag, GetTag, FindGroupfolders)
│   ├── Controller/           # OCS REST API controllers
│   ├── DAV/                  # WebDAV integration (SabreDAV plugins & collections)
│   ├── Db/                   # Database entities and mappers (Tag, TagMapper)
│   ├── Errors/               # Custom exceptions (GroupfolderNotFound, TagNotFound, …)
│   ├── Event/                # Domain events
│   ├── Folder/               # Core folder management (FolderManager)
│   ├── Listeners/            # Event listeners (CacheListener, …)
│   ├── Migration/            # DB schema migrations
│   ├── Mount/                # Nextcloud VFS mount integration
│   ├── Service/              # Business logic (TagService, …)
│   ├── Settings/             # Admin settings page
│   ├── Trash/                # Trash backend for group folder storage
│   └── Versions/             # Versioning backend for group folder storage
├── src/                      # Vue.js frontend (admin settings UI)
├── tests/                    # PHPUnit tests
├── cypress/                  # Cypress E2E tests
├── openapi.json              # OpenAPI specification for REST API
└── README.md                 # User-facing documentation
```

---

## Architecture Patterns

### Dependency Injection
- All classes use constructor injection via Nextcloud's DI container.
- Services, mappers, and commands are auto-wired through `AppInfo/Application.php`.

### Database (Mapper pattern)
- Entity classes extend `OCP\AppFramework\Db\Entity` (e.g., `lib/Db/Tag.php`).
- Mapper classes extend `OCP\AppFramework\Db\QBMapper` and contain all SQL queries (e.g., `lib/Db/TagMapper.php`).
- DB migrations live in `lib/Migration/` and are named `Version<semver><timestamp>.php`.

### ACL / Advanced Permissions
- `ACLManager` uses `CappedMemoryCache` for request-scoped in-memory caching of ACL rules, reducing redundant DB queries.
- `ACLCacheWrapper` wraps Nextcloud's file cache to apply permission masks.
- Rules are fetched by `RuleManager` from the `group_folders_acl` table.

### Tag System (v22+)
- Tags are key-value pairs attached to a Team folder, stored in the `groupfolder_tags` table.
- `TagService` is the service layer; `TagMapper` handles all DB access.
- Three OCC commands expose tag management (see below).

### OCC Commands
All commands extend `FolderCommand` (or `TagCommand` for tag operations) and are registered in `appinfo/info.xml`.

---

## OCC Commands Reference

| Command | Description |
|---|---|
| `occ groupfolders:create <name>` | Create a new Team folder |
| `occ groupfolders:delete <folder_id>` | Delete a Team folder and all its contents |
| `occ groupfolders:list` | List all configured Team folders |
| `occ groupfolders:rename <folder_id> <name>` | Rename a Team folder |
| `occ groupfolders:quota <folder_id> [<quota>\|unlimited]` | Set storage quota |
| `occ groupfolders:group <folder_id> <group_id> [write\|share\|delete]` | Assign group with permissions |
| `occ groupfolders:permissions <folder_id>` | Manage advanced ACL permissions |
| `occ groupfolders:scan <folder_id>` | Trigger a file-cache scan |
| `occ groupfolders:expire` | Trigger version and trash expiration |
| `occ groupfolders:trashbin:cleanup` | Empty the trash for all Team folders |
| `occ groupfolders:tag:set <folder_id> <key> [<value>]` | Add or update a tag on a Team folder |
| `occ groupfolders:tag:get <folder_id> [<key>]` | Get one or all tags for a Team folder |
| `occ groupfolders:tag:find-groupfolders <key> [<value>]` | Find Team folders matching a tag |

---

## Development Workflow

### Running Tests
```bash
# PHPUnit (requires a running Nextcloud instance or test DB)
composer install
./vendor/bin/phpunit -c tests/phpunit.xml

# E2E (Cypress) – requires a running Nextcloud instance
npm install
npx cypress run
```

### Linting & Static Analysis
```bash
# PHP CS Fixer
./vendor/bin/php-cs-fixer fix --dry-run

# PHPStan
./vendor/bin/phpstan analyse

# ESLint (frontend)
npm run lint

# Stylelint (frontend)
npm run stylelint
```

### Frontend Build
```bash
npm install
npm run build        # Production build
npm run dev          # Development watch mode
```

### Database Migrations
When changing the DB schema:
1. Create a new migration file in `lib/Migration/` following the naming convention `Version<MAJOR><MINOR><PATCH>Date<YYYYMMDD><HHMMSS>.php`.
2. Extend `SimpleMigrationStep` and implement `changeSchema()`.
3. Register the migration by bumping `<version>` in `appinfo/info.xml`.

---

## Key Conventions

- **PHP**: `declare(strict_types=1)` in every file; `readonly` constructor properties; `#[\Override]` attribute for overridden methods.
- **SPDX headers**: Every source file must include a SPDX copyright and license header (see `REUSE.toml`).
- **Error handling**: Throw domain-specific exceptions from `lib/Errors/` rather than generic ones.
- **Output format**: OCC commands support `--output=json` via the `writeTableInOutputFormat()` helper.
- **Namespace**: `OCA\GroupFolders\*` throughout.

---

## Recent Changes (v22.0.0)

### Performance: Request-scoped ACL caching (PR #3)
`ACLManager` now uses `CappedMemoryCache` instances (`$ruleCache`, `$basePermissionCache`) to store ACL rule lookups within the scope of a single request. This eliminates redundant database queries when the same paths are checked multiple times during a request (e.g., folder listing operations).

### Feature: Tag management system integrated from `groupfolder_tags` (PR #4)
Key-value tags can now be attached directly to Team folders without requiring a separate plugin:
- New DB table `groupfolder_tags` (created by migration `Version2200000Date20260512000000`).
- `lib/Db/Tag.php` + `lib/Db/TagMapper.php` — entity and data-access layer.
- `lib/Service/TagService.php` — service layer with CRUD, filter, and generator methods.
- `lib/Errors/TagNotFound.php`, `GroupfolderNotFound.php`, `NotFoundException.php` — typed exceptions.
- Three new OCC commands: `groupfolders:tag:set`, `groupfolders:tag:get`, `groupfolders:tag:find-groupfolders`.
