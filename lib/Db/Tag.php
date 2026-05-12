<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Db;

use JsonSerializable;
use OCP\AppFramework\Db\Entity;

class Tag extends Entity implements JsonSerializable {
	protected ?int $groupFolderId = null;
	protected ?string $tagKey = null;
	protected ?string $tagValue = null;
	protected ?int $lastUpdatedTimestamp = null;

	public function __construct() {
		$this->addType('groupFolderId', 'integer');
		$this->addType('lastUpdatedTimestamp', 'integer');
	}

	public function jsonSerialize(): array {
		return [
			'groupFolderId' => $this->groupFolderId,
			'tagKey' => $this->tagKey,
			'tagValue' => $this->tagValue,
			'lastUpdatedTimestamp' => $this->lastUpdatedTimestamp,
		];
	}
}
