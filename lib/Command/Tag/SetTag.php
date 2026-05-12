<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Jonathan Treffler <mail@jonathan-treffler.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Command\Tag;

use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class SetTag extends TagCommand {
	#[\Override]
	protected function configure(): void {
		$this
			->setName('groupfolders:tag:set')
			->setDescription('Add or update a key-value tag on a Team folder')
			->addArgument('folder_id', InputArgument::REQUIRED, 'ID of the Team folder')
			->addArgument('key', InputArgument::REQUIRED, 'Tag key')
			->addArgument('value', InputArgument::OPTIONAL, 'Tag value');
		parent::configure();
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$errors = [];

		/** @var string $folderIdString */
		$folderIdString = $input->getArgument('folder_id');
		/** @var string $tagKey */
		$tagKey = $input->getArgument('key');
		/** @var string|null $tagValue */
		$tagValue = $input->getArgument('value');

		if (!is_numeric($folderIdString)) {
			$errors[] = 'Folder id argument is not an integer. Got ' . $folderIdString;
		}

		if ($tagKey === '') {
			$errors[] = 'No tag key provided';
		}

		if (!empty($errors)) {
			$output->writeln('<error>' . implode("\n", $errors) . '</error>');
			return 1;
		}

		$tag = $this->service->update((int)$folderIdString, $tagKey, $tagValue);
		$this->writeTableInOutputFormat($input, $output, [$this->formatTagEntity($tag)]);

		return 0;
	}
}
