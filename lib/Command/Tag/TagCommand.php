<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Command\Tag;

use OCA\GroupFolders\Command\FolderCommand;
use OCA\GroupFolders\Db\Tag;
use OCA\GroupFolders\Folder\FolderManager;
use OCA\GroupFolders\Mount\FolderStorageManager;
use OCA\GroupFolders\Mount\MountProvider;
use OCA\GroupFolders\Service\TagService;
use OCP\Files\FileInfo;
use OCP\Files\IRootFolder;
use OCP\IDateTimeFormatter;
use OCP\Util;

abstract class TagCommand extends FolderCommand {
	public function __construct(
		FolderManager $folderManager,
		IRootFolder $rootFolder,
		MountProvider $mountProvider,
		FolderStorageManager $folderStorageManager,
		protected readonly TagService $service,
		private readonly IDateTimeFormatter $dateTimeFormatter,
	) {
		parent::__construct($folderManager, $rootFolder, $mountProvider, $folderStorageManager);
	}

	/**
	 * @return array<string, mixed>
	 */
	protected function formatTagEntity(Tag $tag): array {
		return [
			'Groupfolder ID' => $tag->getGroupFolderId(),
			'Key' => $tag->getTagKey(),
			'Value' => $tag->getTagValue(),
			'Last Updated' => $this->dateTimeFormatter->formatDateTime($tag->getLastUpdatedTimestamp()),
		];
	}

	/**
	 * @param Tag[] $tags
	 * @return array<int, array<string, mixed>>
	 */
	protected function formatTagEntities(array $tags): array {
		return array_map($this->formatTagEntity(...), $tags);
	}

	/**
	 * @param array<string, mixed> $groupfolder
	 * @return array<string, mixed>
	 */
	protected function formatGroupfolderArray(array $groupfolder): array {
		$quota = (int)$groupfolder['quota'];

		if ($quota === FolderManager::SPACE_DEFAULT) {
			$humanQuota = 'Default';
		} elseif ($quota === FileInfo::SPACE_UNLIMITED) {
			$humanQuota = 'Unlimited';
		} else {
			$humanQuota = Util::humanFileSize($quota) . ' (' . $quota . ' bytes)';
		}

		return [
			'Groupfolder ID' => $groupfolder['folder_id'],
			'Mount Point' => $groupfolder['mount_point'],
			'Quota' => $humanQuota,
			'ACLs enabled' => $groupfolder['acl'] ? 'yes' : 'no',
		];
	}
}
