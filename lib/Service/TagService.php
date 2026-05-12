<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Service;

use OCA\GroupFolders\Db\Tag;
use OCA\GroupFolders\Db\TagMapper;
use OCA\GroupFolders\Errors\TagNotFound;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\MultipleObjectsReturnedException;

class TagService {
	public function __construct(
		private readonly TagMapper $mapper,
	) {
	}

	/**
	 * @return Tag[]
	 */
	public function findAllWithTagKey(string $tagKey, ?string $tagValue): array {
		return $this->mapper->findAll($tagKey, $tagValue);
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public function findAllIncludingGroupfolder(string $tagKey, ?string $tagValue = null): array {
		return $this->mapper->findAllIncludingGroupfolder($tagKey, $tagValue);
	}

	/**
	 * @param array<int, array{key: string, value?: string, includeInOutput?: bool}> $filters
	 * @param list<string> $additionalReturnTags
	 * @return array<int, array<string, mixed>>
	 */
	public function findGroupfoldersWithTags(array $filters, array $additionalReturnTags = []): array {
		return $this->mapper->findGroupfoldersWithTags($filters, $additionalReturnTags);
	}

	/**
	 * @param array<int, array{key: string, value?: string, includeInOutput?: bool}> $filters
	 * @param list<string> $additionalReturnTags
	 * @return \Generator<int, array<string, mixed>>
	 */
	public function findGroupfoldersWithTagsGenerator(array $filters, array $additionalReturnTags = []): \Generator {
		return $this->mapper->findGroupfoldersWithTagsGenerator($filters, $additionalReturnTags);
	}

	/**
	 * @throws TagNotFound
	 */
	public function find(int $groupFolderId, string $tagKey): Tag {
		try {
			return $this->mapper->find($groupFolderId, $tagKey);
		} catch (\Exception $e) {
			if ($e instanceof DoesNotExistException || $e instanceof MultipleObjectsReturnedException) {
				throw new TagNotFound($groupFolderId, $tagKey);
			}
			throw $e;
		}
	}

	/**
	 * @param array<int, array{key: string, value?: string, includeInOutput?: bool}> $filters
	 * @param list<string> $additionalReturnTags
	 * @return array<string, mixed>|null
	 */
	public function findGroupfolderWithTags(int $groupFolderId, array $filters, array $additionalReturnTags = []): ?array {
		try {
			return $this->mapper->findGroupfolderWithTags($groupFolderId, $filters, $additionalReturnTags);
		} catch (DoesNotExistException) {
			return null;
		}
	}

	/**
	 * Creates or updates a tag on a groupfolder.
	 */
	public function update(int $groupFolderId, string $key, ?string $value = null): Tag {
		try {
			$tag = $this->find($groupFolderId, $key);
			$tagExists = true;
		} catch (TagNotFound) {
			$tag = new Tag();
			$tag->setGroupFolderId($groupFolderId);
			$tag->setTagKey($key);
			$tagExists = false;
		}

		$tag->setTagValue($value);
		$tag->setLastUpdatedTimestamp(time());

		if ($tagExists) {
			return $this->mapper->update($tag);
		}

		return $this->mapper->insert($tag);
	}

	/**
	 * @throws TagNotFound
	 */
	public function delete(int $groupFolderId, string $tagKey): Tag {
		try {
			$tag = $this->mapper->find($groupFolderId, $tagKey);
			$this->mapper->delete($tag);
			return $tag;
		} catch (\Exception $e) {
			if ($e instanceof DoesNotExistException || $e instanceof MultipleObjectsReturnedException) {
				throw new TagNotFound($groupFolderId, $tagKey);
			}
			throw $e;
		}
	}

	/**
	 * @return Tag[]
	 * @throws \OCP\DB\Exception
	 */
	public function findByGroupFolderAndKey(int $groupFolderId, ?string $key): array {
		return $this->mapper->findByGroupFolderAndKey($groupFolderId, $key);
	}

	/**
	 * @return list<int>
	 * @throws \OCP\DB\Exception
	 */
	public function findGroupfoldersWithTag(string $key, ?string $value): array {
		return $this->mapper->findGroupfoldersWithTag($key, $value);
	}
}
