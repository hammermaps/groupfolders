<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\DB\Types;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;
use Override;

/**
 * Creates the groupfolder_tags table, which stores key-value tags for Team folders.
 * Ported from https://github.com/verdigado/groupfolder_tags
 */
class Version2200000Date20260512000000 extends SimpleMigrationStep {
	public const GROUP_FOLDER_TAGS_TABLE = 'groupfolder_tags';
	public const GROUP_FOLDERS_TABLE = 'group_folders';

	#[Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if ($schema->hasTable(self::GROUP_FOLDER_TAGS_TABLE)) {
			return null;
		}

		$table = $schema->createTable(self::GROUP_FOLDER_TAGS_TABLE);

		$table->addColumn('id', Types::INTEGER, [
			'autoincrement' => true,
			'notnull' => true,
		]);
		$table->addColumn('group_folder_id', Types::BIGINT, [
			'notnull' => true,
			'length' => 20,
		]);
		$table->addColumn('tag_key', Types::STRING, [
			'notnull' => true,
			'length' => 50,
		]);
		$table->addColumn('tag_value', Types::STRING, [
			'notnull' => false,
			'length' => 200,
		]);
		$table->addColumn('last_updated_timestamp', Types::BIGINT, [
			'notnull' => true,
		]);

		$table->setPrimaryKey(['id']);
		$table->addUniqueIndex(['group_folder_id', 'tag_key'], 'groupfolder_tags_folder_id_key_idx');
		$table->addIndex(['group_folder_id'], 'groupfolder_tags_folder_id_idx');
		$table->addForeignKeyConstraint(
			$schema->getTable(self::GROUP_FOLDERS_TABLE),
			['group_folder_id'],
			['folder_id'],
			['onDelete' => 'CASCADE'],
			'groupfolder_tags_folder_id_fk',
		);

		return $schema;
	}
}
