<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCP\Files\Config;

use OCP\Files\Mount\IMountPoint;
use OCP\Files\Storage\IStorageFactory;

/**
 * Compatibility shim for Nextcloud versions older than 33.0.0 that do not
 * include IPartialMountProvider.
 *
 * This file is only loaded when the interface is absent from the running
 * Nextcloud instance, allowing the app to boot on NC 32.x without errors
 * while still taking advantage of the optimised path-based mount API on
 * NC 33+.
 *
 * @since 33.0.0 (upstream)
 */
interface IPartialMountProvider extends IMountProvider {
	/**
	 * Get the mounts for a user by path.
	 *
	 * @param string $setupPathHint path for which the mounts are being set up.
	 * @param bool $forChildren when true, only child mounts for $setupPathHint were requested.
	 * @param array $mountProviderArgs The data for the mount which should be provided.
	 * @param IStorageFactory $loader
	 * @return array<string, IMountPoint> IMountPoint instances, indexed by mount-point
	 */
	public function getMountsForPath(
		string $setupPathHint,
		bool $forChildren,
		array $mountProviderArgs,
		IStorageFactory $loader,
	): array;
}
