#!/usr/bin/env node

/**
 * Aegis Egress Gateway Entry Point (Backward compatibility shim)
 * Delegates directly to compiled TypeScript modular distribution (dist/src/index.js)
 */

import '../dist/src/index.js';
export * from '../dist/src/index.js';
