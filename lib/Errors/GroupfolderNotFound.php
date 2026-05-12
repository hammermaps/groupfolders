<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Errors;

class GroupfolderNotFound extends NotFoundException {
	public function __construct(int $id) {
		parent::__construct('groupfolder', ['id' => $id]);
	}
}
