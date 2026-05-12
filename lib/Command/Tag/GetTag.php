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

class GetTag extends TagCommand {
	#[\Override]
	protected function configure(): void {
		$this
			->setName('groupfolders:tag:get')
			->setDescription('Get tag(s) for a Team folder. Omit key to retrieve all tags.')
			->addArgument('folder_id', InputArgument::REQUIRED, 'ID of the Team folder')
			->addArgument('key', InputArgument::OPTIONAL, 'Tag key (omit to get all tags)');
		parent::configure();
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		if (!$this->getFolder($input, $output)) {
			return 1;
		}

		/** @var string $folderIdString */
		$folderIdString = $input->getArgument('folder_id');
		/** @var string|null $tagKey */
		$tagKey = $input->getArgument('key');

		try {
			$tags = $this->service->findByGroupFolderAndKey((int)$folderIdString, $tagKey);

			if (empty($tags)) {
				$output->writeln('<error>No tags found for the given Team folder</error>');
				return 1;
			}

			$this->writeTableInOutputFormat($input, $output, $this->formatTagEntities($tags));

			return 0;
		} catch (Exception $e) {
			$output->writeln('<error>' . $e->getMessage() . '</error>');
			return 1;
		}
	}
}
