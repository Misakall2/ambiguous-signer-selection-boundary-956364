# Windows environment

Upstream: https://github.com/cisco/node-jose

Upstream commit: 37db9e5371dc9a0557767a6a0190e2b0ab5cf3b6

Python 3.11.5 and Node.js 24.16.0 are available. Keep local credentials outside this repository.

Install dependencies with `npm install --ignore-scripts --no-audit --no-fund`. The development jose-cookbook dependency is fetched from its public Git repository. Run `node node_modules/mocha/bin/mocha.js "./test/**/*-test.js"`.
