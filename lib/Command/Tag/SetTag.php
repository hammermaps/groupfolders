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
		$folder = $this->getFolder($input, $output);
		if ($folder === null) {
			return 1;
		}

		/** @var string $tagKey */
		$tagKey = $input->getArgument('key');
		/** @var string|null $tagValue */
		$tagValue = $input->getArgument('value');

		if ($tagKey === '') {
			$output->writeln('<error>No tag key provided</error>');
			return 1;
		}

		$tag = $this->service->update($folder->id, $tagKey, $tagValue);
		$this->writeTableInOutputFormat($input, $output, [$this->formatTagEntity($tag)]);

		return 0;
	}
}
