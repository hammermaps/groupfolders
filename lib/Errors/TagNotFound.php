<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Errors;

use OCA\GroupFolders\Db\Tag;

class TagNotFound extends NotFoundException {
	public function __construct(int $groupFolderId, string $tagKey) {
		parent::__construct(Tag::class, ['groupFolderId' => $groupFolderId, 'tagKey' => $tagKey]);
	}
}
