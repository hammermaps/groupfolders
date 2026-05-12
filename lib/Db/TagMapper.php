<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Db;

use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\Entity;
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

	private function filterGroupfolderQuery(IQueryBuilder $qb, array $filters): void {
		$index = 0;
		foreach ($filters as $filter) {
			$alias = 'filter_' . $index;
			$joinConditions = [
				$qb->expr()->eq($alias . '.group_folder_id', 'g.folder_id'),
				$qb->expr()->eq($alias . '.tag_key', $qb->createNamedParameter($filter['key']))
			];

			if (isset($filter['value'])) {
				$joinConditions[] = $qb->expr()->eq($alias . '.tag_value', $qb->createNamedParameter($filter['value']));
			}

			$qb->innerJoin('g', self::TABLENAME, $alias, $qb->expr()->andX(...$joinConditions));

			if (isset($filter['includeInOutput']) && $filter['includeInOutput'] === true) {
				$qb->selectAlias($alias . '.tag_value', $filter['key']);
			}

			$index++;
		}
	}

	private function addAdditionalReturnTagsToGroupfolderQuery(IQueryBuilder $qb, array $additionalReturnTags): void {
		$index = 0;
		foreach ($additionalReturnTags as $additionalReturnTag) {
			$alias = 'additional_' . $index;

			$qb->leftJoin('g', self::TABLENAME, $alias, $qb->expr()->andX(
				$qb->expr()->eq($alias . '.group_folder_id', 'g.folder_id'),
				$qb->expr()->eq($alias . '.tag_key', $qb->createNamedParameter($additionalReturnTag))
			));

			$qb->selectAlias($alias . '.tag_value', $additionalReturnTag);

			$index++;
		}
	}

	private function findGroupfoldersWithTagsQueryBuilder(array $filters, array $additionalReturnTags = []): IQueryBuilder {
		$qb = $this->db->getQueryBuilder();
		$qb->select('g.mount_point', 'g.quota', 'g.acl', 'g.root_id', 'g.storage_id', 'g.options')
			->selectAlias('g.folder_id', 'id')
			->from(self::GROUP_FOLDERS_TABLENAME, 'g');

		$this->filterGroupfolderQuery($qb, $filters);
		$this->addAdditionalReturnTagsToGroupfolderQuery($qb, $additionalReturnTags);

		return $qb;
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

		$this->filterGroupfolderQuery($qb, $filters);
		$this->addAdditionalReturnTagsToGroupfolderQuery($qb, $additionalReturnTags);

		return $this->findOneQuery($qb);
	}

	/**
	 * @param array<int, array{key: string, value?: string, includeInOutput?: bool}> $filters
	 * @param list<string> $additionalReturnTags
	 * @return array<int, array<string, mixed>>
	 */
	public function findGroupfoldersWithTags(array $filters, array $additionalReturnTags = []): array {
		return $this->findGroupfoldersWithTagsQueryBuilder($filters, $additionalReturnTags)->executeQuery()->fetchAll();
	}

	/**
	 * @param array<int, array{key: string, value?: string, includeInOutput?: bool}> $filters
	 * @param list<string> $additionalReturnTags
	 * @return \Generator<int, array<string, mixed>>
	 */
	public function findGroupfoldersWithTagsGenerator(array $filters, array $additionalReturnTags = []): \Generator {
		$result = $this->findGroupfoldersWithTagsQueryBuilder($filters, $additionalReturnTags)->executeQuery();

		try {
			while ($row = $result->fetch()) {
				yield $row;
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
