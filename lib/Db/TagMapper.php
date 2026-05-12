<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Db;

use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\QBMapper;
use OCP\DB\Exception;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * @template-extends QBMapper<Tag>
 */
class TagMapper extends QBMapper {
	public const TABLENAME = 'groupfolder_tags';
	public const GROUP_FOLDERS_TABLENAME = 'group_folders';

	public function __construct(IDBConnection $db) {
		parent::__construct($db, self::TABLENAME, Tag::class);
	}

	/**
	 * @throws \OCP\AppFramework\Db\MultipleObjectsReturnedException
	 * @throws DoesNotExistException
	 */
	public function find(int $groupFolderId, string $tagKey): Tag {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLENAME)
			->where($qb->expr()->eq('group_folder_id', $qb->createNamedParameter($groupFolderId, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('tag_key', $qb->createNamedParameter($tagKey)));

		return $this->findEntity($qb);
	}

	/**
	 * @return array<string, mixed>
	 * @throws \OCP\AppFramework\Db\MultipleObjectsReturnedException
	 * @throws DoesNotExistException
	 */
	public function findIncludingGroupfolder(int $groupFolderId, string $tagKey): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLENAME, 't')
			->where($qb->expr()->eq('group_folder_id', $qb->createNamedParameter($groupFolderId, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('tag_key', $qb->createNamedParameter($tagKey)))
			->leftJoin('t', self::GROUP_FOLDERS_TABLENAME, 'g', $qb->expr()->andX(
				$qb->expr()->eq('t.group_folder_id', 'g.folder_id'),
			));

		return $this->findOneQuery($qb);
	}

	/**
	 * @return Tag[]
	 */
	public function findAll(string $tagKey, ?string $tagValue): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLENAME)
			->where($qb->expr()->eq('tag_key', $qb->createNamedParameter($tagKey)));

		if (isset($tagValue)) {
			$qb->andWhere($qb->expr()->eq('tag_value', $qb->createNamedParameter($tagValue)));
		}

		return $this->findEntities($qb);
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public function findAllIncludingGroupfolder(string $tagKey, ?string $tagValue = null): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLENAME, 't')
			->where($qb->expr()->eq('tag_key', $qb->createNamedParameter($tagKey)));

		if (isset($tagValue)) {
			$qb->andWhere($qb->expr()->eq('tag_value', $qb->createNamedParameter($tagValue)));
		}

		$qb->leftJoin('t', self::GROUP_FOLDERS_TABLENAME, 'g', $qb->expr()->andX(
			$qb->expr()->eq('t.group_folder_id', 'g.folder_id'),
		));

		return $qb->executeQuery()->fetchAll();
	}

	/**
	 * @param array<int, array{key: string, value?: string, includeInOutput?: bool}> $filters
	 * @return array<string, string> Map of safe SQL alias => original tag key (for filters with includeInOutput === true)
	 */
	private function filterGroupfolderQuery(IQueryBuilder $qb, array $filters): array {
		$aliasMap = [];
		$index = 0;
		foreach ($filters as $filter) {
			$tableAlias = 'filter_' . $index;
			$joinConditions = [
				$qb->expr()->eq($tableAlias . '.group_folder_id', 'g.folder_id'),
				$qb->expr()->eq($tableAlias . '.tag_key', $qb->createNamedParameter($filter['key']))
			];

			if (isset($filter['value'])) {
				$joinConditions[] = $qb->expr()->eq($tableAlias . '.tag_value', $qb->createNamedParameter($filter['value']));
			}

			$qb->innerJoin('g', self::TABLENAME, $tableAlias, $qb->expr()->andX(...$joinConditions));

			if (isset($filter['includeInOutput']) && $filter['includeInOutput'] === true) {
				$safeAlias = 'tag_filter_' . $index;
				$qb->selectAlias($tableAlias . '.tag_value', $safeAlias);
				$aliasMap[$safeAlias] = $filter['key'];
			}

			$index++;
		}
		return $aliasMap;
	}

	/**
	 * @param list<string> $additionalReturnTags
	 * @return array<string, string> Map of safe SQL alias => original tag key
	 */
	private function addAdditionalReturnTagsToGroupfolderQuery(IQueryBuilder $qb, array $additionalReturnTags): array {
		$aliasMap = [];
		$index = 0;
		foreach ($additionalReturnTags as $additionalReturnTag) {
			$tableAlias = 'additional_' . $index;
			$safeAlias = 'tag_additional_' . $index;

			$qb->leftJoin('g', self::TABLENAME, $tableAlias, $qb->expr()->andX(
				$qb->expr()->eq($tableAlias . '.group_folder_id', 'g.folder_id'),
				$qb->expr()->eq($tableAlias . '.tag_key', $qb->createNamedParameter($additionalReturnTag))
			));

			$qb->selectAlias($tableAlias . '.tag_value', $safeAlias);
			$aliasMap[$safeAlias] = $additionalReturnTag;

			$index++;
		}
		return $aliasMap;
	}

	/**
	 * Remap safe SQL aliases back to their original tag key names in a result row.
	 *
	 * @param array<string, mixed> $row
	 * @param array<string, string> $aliasMap safe alias => original key
	 * @return array<string, mixed>
	 */
	private function remapTagAliases(array $row, array $aliasMap): array {
		foreach ($aliasMap as $safeAlias => $originalKey) {
			if (array_key_exists($safeAlias, $row)) {
				$row[$originalKey] = $row[$safeAlias];
				unset($row[$safeAlias]);
			}
		}
		return $row;
	}

	/**
	 * @return array{IQueryBuilder, array<string, string>}
	 */
	private function findGroupfoldersWithTagsQueryBuilder(array $filters, array $additionalReturnTags = []): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('g.mount_point', 'g.quota', 'g.acl', 'g.root_id', 'g.storage_id', 'g.options')
			->selectAlias('g.folder_id', 'id')
			->from(self::GROUP_FOLDERS_TABLENAME, 'g');

		$aliasMap = array_merge(
			$this->filterGroupfolderQuery($qb, $filters),
			$this->addAdditionalReturnTagsToGroupfolderQuery($qb, $additionalReturnTags),
		);

		return [$qb, $aliasMap];
	}

	/**
	 * Get a single groupfolder by id, only if all filters match it.
	 *
	 * Filter format: indexed array of associative arrays with attributes: key, value, includeInOutput.
	 * Returns array with groupfolder attributes (id, mount_point, quota, acl, root_id, storage_id, options)
	 * and the values of additionalReturnTags and filters with includeInOutput === true.
	 *
	 * @param array<int, array{key: string, value?: string, includeInOutput?: bool}> $filters
	 * @param list<string> $additionalReturnTags
	 * @return array<string, mixed>
	 * @throws DoesNotExistException
	 * @throws \OCP\AppFramework\Db\MultipleObjectsReturnedException
	 */
	public function findGroupfolderWithTags(int $groupFolderId, array $filters, array $additionalReturnTags = []): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('g.mount_point', 'g.quota', 'g.acl', 'g.root_id', 'g.storage_id', 'g.options')
			->selectAlias('g.folder_id', 'id')
			->from(self::GROUP_FOLDERS_TABLENAME, 'g')
			->where($qb->expr()->eq('g.folder_id', $qb->createNamedParameter($groupFolderId, IQueryBuilder::PARAM_INT)));

		$aliasMap = array_merge(
			$this->filterGroupfolderQuery($qb, $filters),
			$this->addAdditionalReturnTagsToGroupfolderQuery($qb, $additionalReturnTags),
		);

		$row = $this->findOneQuery($qb);
		return $this->remapTagAliases($row, $aliasMap);
	}

	/**
	 * @param array<int, array{key: string, value?: string, includeInOutput?: bool}> $filters
	 * @param list<string> $additionalReturnTags
	 * @return array<int, array<string, mixed>>
	 */
	public function findGroupfoldersWithTags(array $filters, array $additionalReturnTags = []): array {
		[$qb, $aliasMap] = $this->findGroupfoldersWithTagsQueryBuilder($filters, $additionalReturnTags);
		$rows = $qb->executeQuery()->fetchAll();
		return array_map(fn (array $row): array => $this->remapTagAliases($row, $aliasMap), $rows);
	}

	/**
	 * @param array<int, array{key: string, value?: string, includeInOutput?: bool}> $filters
	 * @param list<string> $additionalReturnTags
	 * @return \Generator<int, array<string, mixed>>
	 */
	public function findGroupfoldersWithTagsGenerator(array $filters, array $additionalReturnTags = []): \Generator {
		[$qb, $aliasMap] = $this->findGroupfoldersWithTagsQueryBuilder($filters, $additionalReturnTags);
		$result = $qb->executeQuery();

		try {
			while ($row = $result->fetch()) {
				yield $this->remapTagAliases($row, $aliasMap);
			}
		} finally {
			$result->closeCursor();
		}
	}

	/**
	 * @return Tag[]
	 * @throws Exception
	 */
	public function findByGroupFolderAndKey(int $groupFolderId, ?string $tagKey): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLENAME)
			->where($qb->expr()->eq('group_folder_id', $qb->createNamedParameter($groupFolderId, IQueryBuilder::PARAM_INT)));

		if (isset($tagKey)) {
			$qb->andWhere($qb->expr()->eq('tag_key', $qb->createNamedParameter($tagKey)));
		}

		return $this->findEntities($qb);
	}

	/**
	 * @return list<int>
	 * @throws Exception
	 */
	public function findGroupfoldersWithTag(string $tagKey, ?string $tagValue): array {
		$qb = $this->db->getQueryBuilder();
		$qb->selectDistinct('group_folder_id')
			->from(self::TABLENAME)
			->where($qb->expr()->eq('tag_key', $qb->createNamedParameter($tagKey)));

		if (isset($tagValue)) {
			$qb->andWhere($qb->expr()->eq('tag_value', $qb->createNamedParameter($tagValue)));
		}

		return $qb->executeQuery()->fetchAll(\PDO::FETCH_COLUMN);
	}
}
