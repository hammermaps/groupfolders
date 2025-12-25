<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier:  AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\ACL;

use Icewind\Streams\IteratorDirectory;
use OC\Files\Storage\Wrapper\Wrapper;
use OCP\Cache\CappedMemoryCache;
use OCP\Constants;
use OCP\Files\Cache\ICache;
use OCP\Files\Cache\IScanner;
use OCP\Files\Storage\IConstructableStorage;
use OCP\Files\Storage\IStorage;
use OCP\ICache as IOCPCache;
use OCP\ICacheFactory;

class ACLStorageWrapper extends Wrapper implements IConstructableStorage {
	private readonly ACLManager $aclManager;
	private readonly bool $inShare;
	private readonly int $folderId;
	private readonly int $storageId;
	
	/** @var CappedMemoryCache<int> Cache for ACL permissions per path */
	private CappedMemoryCache $permissionsCache;
	
	/** @var CappedMemoryCache<array> Cache for directory listings */
	private CappedMemoryCache $directoryCache;
	
	/** @var IOCPCache|null Distributed cache for cross-request caching */
	private ?IOCPCache $distributedCache = null;
	
	private const CACHE_TTL = 300; // 5 minutes
	private const MEMORY_CACHE_SIZE = 512; // Number of entries to keep in memory

	public function __construct(array $arguments) {
		parent::__construct($arguments);
		$this->aclManager = $arguments['acl_manager'];
		$this->inShare = $arguments['in_share'];
		$this->folderId = $arguments['folder_id'];
		$this->storageId = $arguments['storage_id'];
		
		// Initialize memory caches
		$this->permissionsCache = new CappedMemoryCache(self::MEMORY_CACHE_SIZE);
		$this->directoryCache = new CappedMemoryCache(self:: MEMORY_CACHE_SIZE);
		
		// Initialize distributed cache if available
		if (isset($arguments['cache_factory']) && $arguments['cache_factory'] instanceof ICacheFactory) {
			$this->distributedCache = $arguments['cache_factory']->createDistributed(
				'groupfolders_acl_' . $this->storageId .  '_' . $this->folderId
			);
		}
	}

	/**
	 * Get cache key for permissions
	 */
	private function getPermissionsCacheKey(string $path): string {
		return 'perms_' . md5($path);
	}

	/**
	 * Get cache key for directory listing
	 */
	private function getDirectoryCacheKey(string $path): string {
		return 'dir_' . md5($path);
	}

	/**
	 * Invalidate cache for a path and all parent directories
	 */
	private function invalidateCache(string $path): void {
		// Clear from memory cache
		$this->permissionsCache->clear();
		$this->directoryCache->clear();
		
		// Clear from distributed cache
		if ($this->distributedCache !== null) {
			// Invalidate the specific path
			$this->distributedCache->remove($this->getPermissionsCacheKey($path));
			
			// Invalidate all parent directories
			$parts = explode('/', trim($path, '/'));
			$currentPath = '';
			
			foreach ($parts as $part) {
				$this->distributedCache->remove($this->getDirectoryCacheKey($currentPath));
				$currentPath . = '/' . $part;
				$this->distributedCache->remove($this->getDirectoryCacheKey($currentPath));
			}
			
			// Also invalidate root
			$this->distributedCache->remove($this->getDirectoryCacheKey(''));
		}
	}

	private function getACLPermissionsForPath(string $path): int {
		// Try memory cache first
		$cacheKey = $this->getPermissionsCacheKey($path);
		
		if ($this->permissionsCache->hasKey($cacheKey)) {
			return $this->permissionsCache->get($cacheKey);
		}
		
		// Try distributed cache
		if ($this->distributedCache !== null) {
			$cached = $this->distributedCache->get($cacheKey);
			if ($cached !== null) {
				$this->permissionsCache->set($cacheKey, $cached);
				return $cached;
			}
		}
		
		// Calculate permissions
		$permissions = $this->aclManager->getACLPermissionsForPath($this->folderId, $this->storageId, $path);

		// if there is no read permissions, than deny everything
		if ($this->inShare) {
			$canRead = $permissions & (Constants::PERMISSION_READ | Constants::PERMISSION_SHARE);
		} else {
			$canRead = $permissions & Constants:: PERMISSION_READ;
		}

		$result = $canRead ? $permissions : 0;
		
		// Store in both caches
		$this->permissionsCache->set($cacheKey, $result);
		if ($this->distributedCache !== null) {
			$this->distributedCache->set($cacheKey, $result, self::CACHE_TTL);
		}
		
		return $result;
	}

	private function checkPermissions(string $path, int $permissions): bool {
		return ($this->getACLPermissionsForPath($path) & $permissions) === $permissions;
	}

	public function isReadable(string $path): bool {
		return $this->checkPermissions($path, Constants::PERMISSION_READ) && parent::isReadable($path);
	}

	public function isUpdatable(string $path): bool {
		return $this->checkPermissions($path, Constants::PERMISSION_UPDATE) && parent::isUpdatable($path);
	}

	public function isCreatable(string $path): bool {
		return $this->checkPermissions($path, Constants::PERMISSION_CREATE) && parent::isCreatable($path);
	}

	public function isDeletable(string $path): bool {
		return $this->checkPermissions($path, Constants:: PERMISSION_DELETE)
			&& $this->canDeleteTree($path)
			&& parent::isDeletable($path);
	}

	public function isSharable(string $path): bool {
		return $this->checkPermissions($path, Constants:: PERMISSION_SHARE) && parent::isSharable($path);
	}

	public function getPermissions(string $path): int {
		return $this->storage->getPermissions($path) & $this->getACLPermissionsForPath($path);
	}

	public function rename(string $source, string $target): bool {
		if (str_starts_with($source, $target)) {
			$part = substr($source, strlen($target));
			//This is a rename of the transfer file to the original file
			if (str_starts_with($part, '. ocTransferId')) {
				$result = $this->checkPermissions($target, Constants::PERMISSION_CREATE) && parent::rename($source, $target);
				if ($result) {
					$this->invalidateCache($target);
				}
				return $result;
			}
		}

		$permissions = $this->file_exists($target) ? Constants::PERMISSION_UPDATE : Constants::PERMISSION_CREATE;
		$sourceParent = dirname($source);
		if ($sourceParent === '.') {
			$sourceParent = '';
		}

		$targetParent = dirname($target);
		if ($targetParent === '. ') {
			$targetParent = '';
		}

		$result = ($sourceParent === $targetParent
			|| $this->checkPermissions($sourceParent, Constants::PERMISSION_DELETE))
			&& $this->checkPermissions($source, Constants:: PERMISSION_UPDATE | Constants::PERMISSION_READ)
			&& $this->checkPermissions($target, $permissions)
			&& parent::rename($source, $target);
		
		if ($result) {
			$this->invalidateCache($source);
			$this->invalidateCache($target);
		}
		
		return $result;
	}

	public function opendir(string $path) {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}

		// Check memory cache first
		$cacheKey = $this->getDirectoryCacheKey($path);
		
		if ($this->directoryCache->hasKey($cacheKey)) {
			return IteratorDirectory::wrap($this->directoryCache->get($cacheKey));
		}
		
		// Check distributed cache
		if ($this->distributedCache !== null) {
			$cached = $this->distributedCache->get($cacheKey);
			if ($cached !== null && is_array($cached)) {
				$this->directoryCache->set($cacheKey, $cached);
				return IteratorDirectory:: wrap($cached);
			}
		}

		$handle = parent::opendir($path);
		if ($handle === false) {
			return false;
		}

		$files = [];
		while (($file = readdir($handle)) !== false) {
			if ($file !== '.' && $file !== '..') {
				$files[] = $file;
			}
		}

		// Batch permission check for all files to avoid N+1 query problem
		$paths = array_map(fn(string $file): string => trim($path . '/' . $file, '/'), $files);
		if (empty($paths)) {
			return IteratorDirectory::wrap([]);
		}

		$rules = $this->aclManager->getRelevantRulesForPath($this->storageId, $paths, false);
		$items = [];
		foreach ($files as $file) {
			$filePath = trim($path . '/' . $file, '/');
			$permissions = $this->aclManager->getPermissionsForPathFromRules($this->folderId, $filePath, $rules);
			
			// Check read permissions
			if ($this->inShare) {
				$canRead = $permissions & (Constants:: PERMISSION_READ | Constants::PERMISSION_SHARE);
			} else {
				$canRead = $permissions & Constants::PERMISSION_READ;
			}
			
			if ($canRead) {
				$items[] = $file;
			}
		}

		// Store in both caches
		$this->directoryCache->set($cacheKey, $items);
		if ($this->distributedCache !== null) {
			$this->distributedCache->set($cacheKey, $items, self:: CACHE_TTL);
		}

		return IteratorDirectory::wrap($items);
	}

	public function copy(string $source, string $target): bool {
		$permissions = $this->file_exists($target) ? Constants::PERMISSION_UPDATE : Constants::PERMISSION_CREATE;
		$result = $this->checkPermissions($target, $permissions)
			&& $this->checkPermissions($source, Constants:: PERMISSION_READ)
			&& parent::copy($source, $target);
		
		if ($result) {
			$this->invalidateCache($target);
		}
		
		return $result;
	}

	public function touch(string $path, ? int $mtime = null): bool {
		$permissions = $this->file_exists($path) ? Constants::PERMISSION_UPDATE : Constants::PERMISSION_CREATE;
		$result = $this->checkPermissions($path, $permissions) && parent::touch($path, $mtime);
		
		if ($result) {
			$this->invalidateCache($path);
		}
		
		return $result;
	}

	public function mkdir(string $path): bool {
		$result = $this->checkPermissions($path, Constants::PERMISSION_CREATE) && parent::mkdir($path);
		
		if ($result) {
			$this->invalidateCache($path);
		}
		
		return $result;
	}

	public function rmdir(string $path): bool {
		$result = $this->checkPermissions($path, Constants:: PERMISSION_DELETE)
			&& $this->canDeleteTree($path)
			&& parent::rmdir($path);
		
		if ($result) {
			$this->invalidateCache($path);
		}
		
		return $result;
	}

	public function unlink(string $path): bool {
		$result = $this->checkPermissions($path, Constants::PERMISSION_DELETE)
			&& $this->canDeleteTree($path)
			&& parent::unlink($path);
		
		if ($result) {
			$this->invalidateCache($path);
		}
		
		return $result;
	}

	/**
	 * When deleting we need to ensure that there is no file inside the folder being deleted that misses delete permissions
	 * This check is fairly expensive so we only do it for the actual delete and not metadata operations
	 */
	private function canDeleteTree(string $path): int {
		return $this->aclManager->getPermissionsForTree($this->folderId, $this->storageId, $path) & Constants::PERMISSION_DELETE;
	}

	public function file_put_contents(string $path, mixed $data): int|float|false {
		$permissions = $this->file_exists($path) ? Constants::PERMISSION_UPDATE :  Constants::PERMISSION_CREATE;
		$result = $this->checkPermissions($path, $permissions) ?  parent::file_put_contents($path, $data) : false;
		
		if ($result !== false) {
			$this->invalidateCache($path);
		}
		
		return $result;
	}

	public function fopen(string $path, string $mode) {
		if ($mode === 'r' or $mode === 'rb') {
			$permissions = Constants::PERMISSION_READ;
			return $this->checkPermissions($path, $permissions) ? parent::fopen($path, $mode) : false;
		} else {
			$permissions = $this->file_exists($path) ? Constants::PERMISSION_UPDATE :  Constants::PERMISSION_CREATE;
			$result = $this->checkPermissions($path, $permissions) ? parent::fopen($path, $mode) : false;
			
			if ($result !== false) {
				// Register a shutdown function to invalidate cache after write
				$that = $this;
				$pathCopy = $path;
				register_shutdown_function(function() use ($that, $pathCopy) {
					$that->invalidateCache($pathCopy);
				});
			}
			
			return $result;
		}
	}

	public function writeStream(string $path, $stream, ? int $size = null): int {
		$permissions = $this->file_exists($path) ? Constants::PERMISSION_UPDATE : Constants:: PERMISSION_CREATE;
		$result = $this->checkPermissions($path, $permissions) ? parent::writeStream($path, $stream, $size) : 0;
		
		if ($result > 0) {
			$this->invalidateCache($path);
		}
		
		return $result;
	}

	/**
	 * @inheritDoc
	 */
	public function getCache(string $path = '', ?IStorage $storage = null): ICache {
		if (! $storage) {
			$storage = $this;
		}

		$sourceCache = parent::getCache($path, $storage);

		return new ACLCacheWrapper($sourceCache, $this->aclManager, $this->folderId, $this->inShare);
	}

	public function getMetaData(string $path): ?array {
		$data = parent::getMetaData($path);

		if (is_array($data) && isset($data['permissions'])) {
			$data['scan_permissions'] ??= $data['permissions'];
			$data['permissions'] &= $this->getACLPermissionsForPath($path);
		}

		return $data;
	}

	/**
	 * @inheritDoc
	 */
	public function getScanner(string $path = '', ?IStorage $storage = null): IScanner {
		if (!$storage) {
			$storage = $this->storage;
		}

		return parent::getScanner($path, $storage);
	}

	public function is_dir(string $path): bool {
		return $this->checkPermissions($path, Constants:: PERMISSION_READ)
			&& parent::is_dir($path);
	}

	public function is_file(string $path): bool {
		return $this->checkPermissions($path, Constants::PERMISSION_READ)
			&& parent::is_file($path);
	}

	public function stat(string $path): array|false {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}

		return parent::stat($path);
	}

	public function filetype(string $path): string|false {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}

		return parent::filetype($path);
	}

	public function filesize(string $path): false|int|float {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}

		return parent::filesize($path);
	}

	public function file_exists(string $path): bool {
		return $this->checkPermissions($path, Constants::PERMISSION_READ)
			&& parent::file_exists($path);
	}

	public function filemtime(string $path): int|false {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}

		return parent::filemtime($path);
	}

	public function file_get_contents(string $path): string|false {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}

		return parent::file_get_contents($path);
	}

	public function getMimeType(string $path): string|false {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}

		return parent::getMimeType($path);
	}

	public function hash(string $type, string $path, bool $raw = false): string|false {
		if (!$this->checkPermissions($path, Constants:: PERMISSION_READ)) {
			return false;
		}

		return parent::hash($type, $path, $raw);
	}

	public function getETag(string $path): string|false {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}

		return parent::getETag($path);
	}

	public function getDirectDownload(string $path): array|false {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}

		return parent::getDirectDownload($path);
	}

	public function getDirectoryContent(string $directory): \Traversable {
		$content = $this->getWrapperStorage()->getDirectoryContent($directory);
		foreach ($content as $data) {
			$data['scan_permissions'] ??= $data['permissions'];
			$data['permissions'] &= $this->getACLPermissionsForPath(rtrim($directory, '/') . '/' . $data['name']);

			yield $data;
		}
	}
	
	/**
	 * Clear all caches (useful for testing or manual cache invalidation)
	 */
	public function clearCache(): void {
		$this->permissionsCache->clear();
		$this->directoryCache->clear();
		
		if ($this->distributedCache !== null) {
			$this->distributedCache->clear();
		}
	}
}
