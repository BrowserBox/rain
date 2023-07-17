#!/usr/bin/env node
import fs from 'fs';
import process from 'process';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { rainstormHash } from './lib/rainstorm.mjs';

const argv = yargs(hideBin(process.argv))
    .usage('Usage: $0 [options] [file]')
    .option('mode', {
        alias: 'm',
        description: 'Mode: digest or stream',
        type: 'string',
    })
    .option('algorithm', {
        alias: 'a',
        description: 'Specify the hash algorithm to use',
        type: 'string',
    })
    .option('size', {
        alias: 's',
        description: 'Specify the size of the hash',
        type: 'number',
    })
    .option('output-file', {
        alias: 'o',
        description: 'Output file for the hash',
        type: 'string',
    })
    .option('seed', {
        description: 'Seed value',
        type: 'string',
    })
    .help()
    .alias('help', 'h')
    .demandCommand(0, 1) // Accepts 0 or 1 positional arguments
    .argv;

async function hashBuffer(mode, algorithm, seed, buffer, outputStream, hashSize, inputName) {
    const hash = await rainstormHash(hashSize, seed, buffer);
    outputStream.write(`${hash} ${inputName}\n`);
}

async function hashAnything(mode, algorithm, seed, inputPath, outputPath, size) {
    let buffer = [];
    let inputName;
    if (inputPath === '/dev/stdin') {
        for await (const chunk of process.stdin) {
            buffer.push(chunk);
        }
        buffer = Buffer.concat(buffer);
        inputName = 'stdin';
    } else {
        buffer = fs.readFileSync(inputPath);
        inputName = inputPath;
    }

    const outputStream = fs.createWriteStream(outputPath, { flags: 'a' });
    await hashBuffer(mode, algorithm, seed, buffer, outputStream, size, inputName);
}

async function main() {
    const mode = argv.mode || 'digest';
    const algorithm = argv.algorithm || 'rainstorm';
    const size = argv.size || 256;
    const seed = BigInt(argv['seed'] || 0);
    const inputPath = argv._[0] || argv['input-file'] || '/dev/stdin';
    const outputPath = argv['output-file'] || '/dev/stdout';

    await hashAnything(mode, algorithm, seed, inputPath, outputPath, size);
}

main();

