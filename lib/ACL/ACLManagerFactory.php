<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\ACL;

use OCA\GroupFolders\ACL\UserMapping\IUserMappingManager;
use OCP\Cache\CappedMemoryCache;
use OCP\IAppConfig;
use OCP\IUser;

class ACLManagerFactory {
	/** @var CappedMemoryCache<ACLManager> */
	private readonly CappedMemoryCache $cache;

	public function __construct(
		private readonly RuleManager $ruleManager,
		private readonly IAppConfig $config,
		private readonly IUserMappingManager $userMappingManager,
	) {
		$this->cache = new CappedMemoryCache();
	}

	public function getACLManager(IUser $user): ACLManager {
		$uid = $user->getUID();
		$inheritPerUser = $this->config->getValueString('groupfolders', 'acl-inherit-per-user', 'false') === 'true';
		$cacheKey = $uid . ':' . ($inheritPerUser ? '1' : '0');
		$cached = $this->cache->get($cacheKey);
		if ($cached !== null) {
			return $cached;
		}

		$manager = new ACLManager(
			$this->ruleManager,
			$this->userMappingManager,
			$user,
			$inheritPerUser,
		);
		$this->cache->set($cacheKey, $manager);
		return $manager;
	}
}
