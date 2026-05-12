<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Command\Tag;

use OCP\DB\Exception;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class FindGroupfolders extends TagCommand {
	#[\Override]
	protected function configure(): void {
		$this
			->setName('groupfolders:tag:find-groupfolders')
			->setDescription('Find all Team folders that have a given tag key, optionally filtered by tag value.')
			->addArgument('key', InputArgument::REQUIRED, 'Tag key to search for')
			->addArgument('value', InputArgument::OPTIONAL, 'Optional tag value filter');
		parent::configure();
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		/** @var string $tagKey */
		$tagKey = $input->getArgument('key');
		/** @var string|null $tagValue */
		$tagValue = $input->getArgument('value');

		try {
			$groupfolders = $this->service->findAllIncludingGroupfolder($tagKey, $tagValue);

			if (empty($groupfolders)) {
				$output->writeln('<error>No matching Team folders found</error>');
				return 1;
			}

			$results = array_map($this->formatGroupfolderArray(...), $groupfolders);
			$this->writeTableInOutputFormat($input, $output, $results);

			return 0;
		} catch (Exception $e) {
			$output->writeln('<error>' . $e->getMessage() . '</error>');
			return 1;
		}
	}
}
