#!/usr/bin/env node
import { runCLI } from '../cli.js';

runCLI().then((exitCode) => {
  process.exit(exitCode);
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
