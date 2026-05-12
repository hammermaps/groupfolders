<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Errors;

abstract class NotFoundException extends \RuntimeException {
	/**
	 * @param class-string|string $entity
	 * @param array<string, mixed>|string $criteria
	 */
	public function __construct(string $entity, array|string $criteria) {
		$entityName = class_exists($entity) ? array_pop(explode('\\', $entity)) : $entity;
		$criteriaString = is_string($criteria) ? $criteria : json_encode($criteria);
		$message = sprintf('Could not find %s with criteria %s', $entityName, $criteriaString);
		parent::__construct($message);
	}
}
