#!/usr/bin/env node

/**
 * @engjts/auth CLI - Janus Token System Command Line Interface
 * 
 * Commands:
 * - jts keygen: Generate key pairs
 * - jts inspect: Decode and display token contents
 * - jts verify: Verify token signature
 * - jts jwks: Convert keys to JWKS format
 * - jts init: Initialize JTS configuration
 */

import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';

import {
  generateKeyPair,
  generateRSAKeyPair,
  generateECKeyPair,
  verify,
  base64urlDecode,
  decodeJSON,
  pemToJwk,
  keyPairToJwks,
  jwkToPem,
  VERSION,
  JTS_SPEC_VERSION,
} from '../index';

import type { JTSAlgorithm, JTSKeyPair, JTSHeader, JTSPayload, JWKS, JWKSKey } from '../types';

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Print styled output
 */
const print = {
  success: (msg: string) => console.log(chalk.green('✓'), msg),
  error: (msg: string) => console.error(chalk.red('✗'), msg),
  warn: (msg: string) => console.log(chalk.yellow('⚠'), msg),
  info: (msg: string) => console.log(chalk.blue('ℹ'), msg),
  header: (msg: string) => console.log(chalk.bold.cyan('\n' + msg)),
  dim: (msg: string) => console.log(chalk.dim(msg)),
  json: (obj: unknown) => console.log(JSON.stringify(obj, null, 2)),
};

/**
 * Format timestamp to readable date
 */
function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp * 1000);
  return date.toISOString();
}

/**
 * Check if token is expired
 */
function isExpired(exp: number): boolean {
  return exp < Math.floor(Date.now() / 1000);
}

/**
 * Get time until expiration
 */
function getTimeRemaining(exp: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = exp - now;
  
  if (diff < 0) {
    const absDiff = Math.abs(diff);
    if (absDiff < 60) return `${absDiff}s ago`;
    if (absDiff < 3600) return `${Math.floor(absDiff / 60)}m ago`;
    if (absDiff < 86400) return `${Math.floor(absDiff / 3600)}h ago`;
    return `${Math.floor(absDiff / 86400)}d ago`;
  }
  
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
  return `${Math.floor(diff / 86400)}d ${Math.floor((diff % 86400) / 3600)}h`;
}

/**
 * Decode a JTS token (JWS format)
 */
function decodeToken(token: string): { header: JTSHeader; payload: JTSPayload; signature: string } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid token format: expected 3 parts');
    }
    
    const header = decodeJSON<JTSHeader>(parts[0]);
    const payload = decodeJSON<JTSPayload>(parts[1]);
    const signature = parts[2];
    
    return { header, payload, signature };
  } catch (err) {
    return null;
  }
}

/**
 * Read file or stdin
 */
async function readInput(filePath?: string): Promise<string> {
  if (filePath && filePath !== '-') {
    return fs.readFileSync(filePath, 'utf8');
  }
  
  // Read from stdin
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });
  
  return new Promise((resolve) => {
    let data = '';
    rl.on('line', (line) => {
      data += line + '\n';
    });
    rl.on('close', () => {
      resolve(data.trim());
    });
  });
}

/**
 * Write output to file or stdout
 */
function writeOutput(content: string, filePath?: string): void {
  if (filePath && filePath !== '-') {
    fs.writeFileSync(filePath, content);
    print.success(`Written to ${filePath}`);
  } else {
    console.log(content);
  }
}

// ============================================================================
// COMMANDS
// ============================================================================

/**
 * keygen command - Generate key pairs
 */
async function keygenCommand(options: {
  algorithm: JTSAlgorithm;
  kid?: string;
  bits?: string;
  output?: string;
  publicOut?: string;
  format: 'pem' | 'jwk';
}) {
  const { algorithm, format, bits } = options;
  const kid = options.kid || `key-${Date.now()}`;
  
  print.header('Generating Key Pair');
  print.info(`Algorithm: ${chalk.bold(algorithm)}`);
  print.info(`Key ID: ${chalk.bold(kid)}`);
  
  try {
    let keyPair: JTSKeyPair;
    
    if (algorithm.startsWith('RS') || algorithm.startsWith('PS')) {
      const modulusLength = bits ? parseInt(bits, 10) : 2048;
      print.info(`Modulus Length: ${chalk.bold(modulusLength)} bits`);
      keyPair = await generateRSAKeyPair(kid, algorithm as any, modulusLength);
    } else {
      keyPair = await generateECKeyPair(kid, algorithm as any);
      print.info(`Curve: ${algorithm === 'ES256' ? 'P-256' : algorithm === 'ES384' ? 'P-384' : 'P-521'}`);
    }
    
    if (format === 'pem') {
      // Output PEM format
      const privateContent = keyPair.privateKey as string;
      const publicContent = keyPair.publicKey as string;
      
      if (options.output) {
        writeOutput(privateContent, options.output);
        const pubPath = options.publicOut || options.output.replace(/\.pem$/, '') + '.pub.pem';
        writeOutput(publicContent, pubPath);
      } else {
        console.log('\n' + chalk.bold('Private Key:'));
        console.log(privateContent);
        console.log(chalk.bold('Public Key:'));
        console.log(publicContent);
      }
    } else {
      // Output JWK format
      const publicJwk = pemToJwk(keyPair.publicKey, kid, algorithm);
      const privateJwk = { ...publicJwk };
      
      // For private JWK, we need to export with private components
      const crypto = await import('crypto');
      const privateKey = crypto.createPrivateKey(keyPair.privateKey as string);
      const exportedPrivate = privateKey.export({ format: 'jwk' });
      Object.assign(privateJwk, exportedPrivate);
      privateJwk.kid = kid;
      privateJwk.use = 'sig';
      privateJwk.alg = algorithm;
      
      if (options.output) {
        writeOutput(JSON.stringify(privateJwk, null, 2), options.output);
        const pubPath = options.publicOut || options.output.replace(/\.json$/, '') + '.pub.json';
        writeOutput(JSON.stringify(publicJwk, null, 2), pubPath);
      } else {
        console.log('\n' + chalk.bold('Private JWK:'));
        print.json(privateJwk);
        console.log('\n' + chalk.bold('Public JWK:'));
        print.json(publicJwk);
      }
    }
    
    print.success('Key pair generated successfully');
  } catch (err) {
    print.error(`Failed to generate key pair: ${(err as Error).message}`);
    process.exit(1);
  }
}

/**
 * inspect command - Decode and display token contents
 */
async function inspectCommand(token: string, options: { json?: boolean }) {
  // Try to read from file if token looks like a path
  let tokenContent = token;
  if (token.endsWith('.jwt') || token.endsWith('.token') || fs.existsSync(token)) {
    try {
      tokenContent = fs.readFileSync(token, 'utf8').trim();
    } catch {
      // Use as-is if can't read as file
    }
  }
  
  // Check if it's a JWE (5 parts)
  const parts = tokenContent.split('.');
  const isJWE = parts.length === 5;
  
  if (isJWE) {
    try {
      const header = decodeJSON<any>(parts[0]);
      
      if (options.json) {
        console.log(JSON.stringify({ header, encrypted: true, parts: 5 }, null, 2));
        return;
      }
      
      print.header('JWE Token (Encrypted)');
      console.log(chalk.bold('\nHeader:'));
      print.json(header);
      
      print.warn('\nPayload is encrypted. Use jts decrypt to view contents.');
      print.dim(`\nKey ID: ${header.kid || 'not specified'}`);
      print.dim(`Algorithm: ${header.alg}`);
      print.dim(`Encryption: ${header.enc}`);
    } catch (err) {
      print.error('Failed to parse JWE header');
      process.exit(1);
    }
    return;
  }
  
  const decoded = decodeToken(tokenContent);
  
  if (!decoded) {
    print.error('Invalid token format. Expected JWS (3 parts separated by dots)');
    process.exit(1);
  }
  
  const { header, payload } = decoded;
  
  if (options.json) {
    console.log(JSON.stringify({ header, payload }, null, 2));
    return;
  }
  
  print.header('JTS Token Details');
  
  // Header
  console.log(chalk.bold('\nHeader:'));
  console.log(`  ${chalk.dim('Algorithm:')}   ${chalk.cyan(header.alg)}`);
  console.log(`  ${chalk.dim('Type:')}        ${chalk.cyan(header.typ)}`);
  console.log(`  ${chalk.dim('Key ID:')}      ${chalk.cyan(header.kid)}`);
  
  // Payload
  console.log(chalk.bold('\nPayload:'));
  console.log(`  ${chalk.dim('Principal:')}   ${chalk.white(payload.prn)}`);
  console.log(`  ${chalk.dim('Anchor ID:')}   ${chalk.white(payload.aid)}`);
  
  if (payload.tkn_id) {
    console.log(`  ${chalk.dim('Token ID:')}    ${chalk.white(payload.tkn_id)}`);
  }
  
  // Timestamps
  console.log(chalk.bold('\nTimestamps:'));
  const expired = isExpired(payload.exp);
  const expColor = expired ? chalk.red : chalk.green;
  console.log(`  ${chalk.dim('Issued At:')}   ${formatTimestamp(payload.iat)} ${chalk.dim('(iat)')}`);
  console.log(`  ${chalk.dim('Expires At:')}  ${expColor(formatTimestamp(payload.exp))} ${chalk.dim('(exp)')}`);
  console.log(`  ${chalk.dim('Status:')}      ${expired ? chalk.red('EXPIRED') : chalk.green('VALID')} (${getTimeRemaining(payload.exp)})`);
  
  // Optional claims
  if (payload.aud) {
    console.log(chalk.bold('\nAudience:'));
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    audiences.forEach(a => console.log(`  ${chalk.dim('•')} ${a}`));
  }
  
  if (payload.perm && payload.perm.length > 0) {
    console.log(chalk.bold('\nPermissions:'));
    payload.perm.forEach(p => console.log(`  ${chalk.dim('•')} ${chalk.yellow(p)}`));
  }
  
  if (payload.org) {
    console.log(chalk.bold('\nOrganization:'));
    console.log(`  ${payload.org}`);
  }
  
  if (payload.dfp) {
    console.log(chalk.bold('\nDevice Fingerprint:'));
    console.log(`  ${chalk.dim(payload.dfp)}`);
  }
  
  if (payload.atm) {
    console.log(chalk.bold('\nAuth Method:'));
    console.log(`  ${payload.atm}`);
  }
  
  if (payload.grc) {
    console.log(chalk.bold('\nGrace Period:'));
    console.log(`  ${payload.grc} seconds`);
  }
  
  // Show any custom claims
  const standardClaims = ['prn', 'aid', 'tkn_id', 'exp', 'iat', 'aud', 'perm', 'org', 'dfp', 'atm', 'grc', 'ath', 'spl'];
  const customClaims = Object.entries(payload).filter(([k]) => !standardClaims.includes(k));
  
  if (customClaims.length > 0) {
    console.log(chalk.bold('\nCustom Claims:'));
    customClaims.forEach(([k, v]) => {
      console.log(`  ${chalk.dim(k + ':')} ${JSON.stringify(v)}`);
    });
  }
}

/**
 * verify command - Verify token signature
 */
async function verifyCommand(token: string, options: { key?: string; jwks?: string }) {
  // Read token
  let tokenContent = token;
  if (token.endsWith('.jwt') || token.endsWith('.token') || fs.existsSync(token)) {
    try {
      tokenContent = fs.readFileSync(token, 'utf8').trim();
    } catch {
      // Use as-is
    }
  }
  
  const decoded = decodeToken(tokenContent);
  if (!decoded) {
    print.error('Invalid token format');
    process.exit(1);
  }
  
  const { header, payload, signature } = decoded;
  
  print.header('Verifying Token');
  print.info(`Algorithm: ${header.alg}`);
  print.info(`Key ID: ${header.kid}`);
  
  // Get public key
  let publicKey: string;
  
  if (options.jwks) {
    // Load from JWKS
    let jwks: JWKS;
    
    if (options.jwks.startsWith('http://') || options.jwks.startsWith('https://')) {
      // Fetch from URL
      print.info(`Fetching JWKS from ${options.jwks}`);
      try {
        const response = await fetch(options.jwks);
        jwks = await response.json() as JWKS;
      } catch (err) {
        print.error(`Failed to fetch JWKS: ${(err as Error).message}`);
        process.exit(1);
      }
    } else {
      // Read from file
      try {
        jwks = JSON.parse(fs.readFileSync(options.jwks, 'utf8'));
      } catch (err) {
        print.error(`Failed to read JWKS file: ${(err as Error).message}`);
        process.exit(1);
      }
    }
    
    // Find key by kid
    const key = jwks.keys.find(k => k.kid === header.kid);
    if (!key) {
      print.error(`Key with kid "${header.kid}" not found in JWKS`);
      print.dim(`Available keys: ${jwks.keys.map(k => k.kid).join(', ')}`);
      process.exit(1);
    }
    
    publicKey = jwkToPem(key);
  } else if (options.key) {
    // Read from file or stdin
    if (options.key === '-') {
      publicKey = await readInput();
    } else {
      try {
        const content = fs.readFileSync(options.key, 'utf8');
        // Check if it's JWK format
        if (content.trim().startsWith('{')) {
          const jwk = JSON.parse(content) as JWKSKey;
          publicKey = jwkToPem(jwk);
        } else {
          publicKey = content;
        }
      } catch (err) {
        print.error(`Failed to read key file: ${(err as Error).message}`);
        process.exit(1);
      }
    }
  } else {
    print.error('Please provide a public key with --key or --jwks');
    process.exit(1);
  }
  
  // Verify signature
  const parts = tokenContent.split('.');
  const signingInput = `${parts[0]}.${parts[1]}`;
  const signatureBuffer = base64urlDecode(signature);
  
  try {
    const isValid = verify(signingInput, signatureBuffer, publicKey, header.alg as JTSAlgorithm);
    
    console.log();
    if (isValid) {
      print.success(chalk.green.bold('Signature is VALID'));
      
      // Check expiration
      if (isExpired(payload.exp)) {
        print.warn('Token has EXPIRED');
        print.dim(`Expired: ${formatTimestamp(payload.exp)} (${getTimeRemaining(payload.exp)})`);
      } else {
        print.success('Token is not expired');
        print.dim(`Expires: ${formatTimestamp(payload.exp)} (${getTimeRemaining(payload.exp)})`);
      }
    } else {
      print.error(chalk.red.bold('Signature is INVALID'));
      process.exit(1);
    }
  } catch (err) {
    print.error(`Verification failed: ${(err as Error).message}`);
    process.exit(1);
  }
}

/**
 * jwks command - Convert keys to JWKS format
 */
async function jwksCommand(keyFiles: string[], options: { output?: string; kid?: string }) {
  print.header('Converting to JWKS');
  
  const keys: JWKSKey[] = [];
  
  for (const file of keyFiles) {
    print.info(`Processing ${file}`);
    
    try {
      const content = fs.readFileSync(file, 'utf8');
      
      // Detect format
      if (content.trim().startsWith('{')) {
        // JWK format - might be single key or JWKS
        const parsed = JSON.parse(content);
        
        if (parsed.keys && Array.isArray(parsed.keys)) {
          // It's already a JWKS
          keys.push(...parsed.keys);
        } else if (parsed.kty) {
          // Single JWK
          keys.push(parsed as JWKSKey);
        } else {
          print.warn(`Unrecognized JSON format in ${file}`);
        }
      } else if (content.includes('-----BEGIN')) {
        // PEM format
        const kid = options.kid || path.basename(file, path.extname(file));
        
        // Try to detect algorithm from key
        let algorithm: JTSAlgorithm = 'RS256';
        if (content.includes('EC ')) {
          // Detect curve from key
          const crypto = await import('crypto');
          const key = crypto.createPublicKey(content);
          const exported = key.export({ format: 'jwk' });
          
          if (exported.crv === 'P-256') algorithm = 'ES256';
          else if (exported.crv === 'P-384') algorithm = 'ES384';
          else if (exported.crv === 'P-521') algorithm = 'ES512';
        }
        
        const jwk = pemToJwk(content, kid, algorithm);
        keys.push(jwk);
      } else {
        print.warn(`Unrecognized format in ${file}`);
      }
    } catch (err) {
      print.error(`Failed to process ${file}: ${(err as Error).message}`);
    }
  }
  
  if (keys.length === 0) {
    print.error('No valid keys found');
    process.exit(1);
  }
  
  const jwks: JWKS = { keys };
  const output = JSON.stringify(jwks, null, 2);
  
  if (options.output) {
    writeOutput(output, options.output);
  } else {
    console.log();
    print.json(jwks);
  }
  
  print.success(`Converted ${keys.length} key(s) to JWKS format`);
}

/**
 * init command - Initialize JTS configuration
 */
async function initCommand(options: { 
  profile: 'JTS-L' | 'JTS-S' | 'JTS-C';
  algorithm: JTSAlgorithm;
  output: string;
  force?: boolean;
}) {
  const { profile, algorithm, output } = options;
  
  print.header('Initializing JTS Configuration');
  print.info(`Profile: ${profile}`);
  print.info(`Algorithm: ${algorithm}`);
  print.info(`Output directory: ${output}`);
  
  // Check if directory exists
  if (fs.existsSync(output) && !options.force) {
    print.error(`Directory ${output} already exists. Use --force to overwrite.`);
    process.exit(1);
  }
  
  // Create directory
  fs.mkdirSync(output, { recursive: true });
  
  try {
    // Generate signing key
    print.info('Generating signing key...');
    const signingKey = await generateKeyPair(`${profile.toLowerCase()}-signing-${Date.now()}`, algorithm);
    
    // Write keys
    fs.writeFileSync(
      path.join(output, 'signing-key.pem'),
      signingKey.privateKey as string
    );
    fs.writeFileSync(
      path.join(output, 'signing-key.pub.pem'),
      signingKey.publicKey as string
    );
    
    // Create JWKS
    const jwks = keyPairToJwks([signingKey]);
    fs.writeFileSync(
      path.join(output, 'jwks.json'),
      JSON.stringify(jwks, null, 2)
    );
    
    // Generate encryption key for JTS-C
    let encryptionKey: JTSKeyPair | undefined;
    if (profile === 'JTS-C') {
      print.info('Generating encryption key...');
      encryptionKey = await generateRSAKeyPair(`${profile.toLowerCase()}-encryption-${Date.now()}`, 'RS256', 2048);
      
      fs.writeFileSync(
        path.join(output, 'encryption-key.pem'),
        encryptionKey.privateKey as string
      );
      fs.writeFileSync(
        path.join(output, 'encryption-key.pub.pem'),
        encryptionKey.publicKey as string
      );
    }
    
    // Create config file
    const config = {
      profile: `${profile}/v1`,
      signingKey: {
        kid: signingKey.kid,
        algorithm,
        privateKeyPath: './signing-key.pem',
        publicKeyPath: './signing-key.pub.pem',
      },
      ...(encryptionKey && {
        encryptionKey: {
          kid: encryptionKey.kid,
          algorithm: 'RSA-OAEP-256',
          privateKeyPath: './encryption-key.pem',
          publicKeyPath: './encryption-key.pub.pem',
        },
      }),
      bearerPassLifetime: 300,
      stateProofLifetime: 604800,
      gracePeriod: 30,
      jwksPath: './jwks.json',
    };
    
    fs.writeFileSync(
      path.join(output, 'jts.config.json'),
      JSON.stringify(config, null, 2)
    );
    
    // Create example usage file
    const exampleCode = `
/**
 * JTS ${profile} Example Usage
 * Generated by jts-cli
 */

import { JTSAuthServer, JTSResourceServer } from '@engjts/auth';
import * as fs from 'fs';
import * as path from 'path';

// Load configuration
const config = JSON.parse(fs.readFileSync('./jts.config.json', 'utf8'));

// Load signing key
const signingKey = {
  kid: config.signingKey.kid,
  algorithm: config.signingKey.algorithm,
  privateKey: fs.readFileSync(config.signingKey.privateKeyPath, 'utf8'),
  publicKey: fs.readFileSync(config.signingKey.publicKeyPath, 'utf8'),
};

// Create Auth Server
const authServer = new JTSAuthServer({
  profile: config.profile,
  signingKey,
  bearerPassLifetime: config.bearerPassLifetime,
  stateProofLifetime: config.stateProofLifetime,
});

// Login example
async function loginUser(userId: string, permissions: string[]) {
  const tokens = await authServer.login({
    prn: userId,
    permissions,
  });
  
  console.log('BearerPass:', tokens.bearerPass);
  console.log('StateProof:', tokens.stateProof);
  console.log('Expires:', new Date(tokens.expiresAt * 1000));
  
  return tokens;
}

// Create Resource Server
const resourceServer = new JTSResourceServer({
  publicKeys: [signingKey],
});

// Verify token example
async function verifyToken(bearerPass: string) {
  const result = await resourceServer.verify(bearerPass);
  
  if (result.valid) {
    console.log('Valid token for:', result.payload?.prn);
    console.log('Permissions:', result.payload?.perm);
  } else {
    console.log('Invalid token:', result.error?.message);
  }
  
  return result;
}

// Run example
(async () => {
  const tokens = await loginUser('user-123', ['read:profile', 'write:posts']);
  await verifyToken(tokens.bearerPass);
})();
`.trim();

    fs.writeFileSync(
      path.join(output, 'example.ts'),
      exampleCode
    );
    
    // Create .gitignore
    const gitignore = `
# JTS Keys - Never commit private keys!
*.pem
!*.pub.pem
`.trim();

    fs.writeFileSync(
      path.join(output, '.gitignore'),
      gitignore
    );
    
    console.log();
    print.success('JTS configuration initialized successfully!');
    console.log();
    print.dim('Generated files:');
    console.log(`  ${chalk.cyan(path.join(output, 'jts.config.json'))} - Configuration file`);
    console.log(`  ${chalk.cyan(path.join(output, 'signing-key.pem'))} - Private signing key`);
    console.log(`  ${chalk.cyan(path.join(output, 'signing-key.pub.pem'))} - Public signing key`);
    console.log(`  ${chalk.cyan(path.join(output, 'jwks.json'))} - JWKS public keys`);
    console.log(`  ${chalk.cyan(path.join(output, 'example.ts'))} - Example usage`);
    if (profile === 'JTS-C') {
      console.log(`  ${chalk.cyan(path.join(output, 'encryption-key.pem'))} - Private encryption key`);
      console.log(`  ${chalk.cyan(path.join(output, 'encryption-key.pub.pem'))} - Public encryption key`);
    }
    
    console.log();
    print.warn('IMPORTANT: Never commit private keys to version control!');
    print.dim('A .gitignore file has been created to help prevent this.');
    
  } catch (err) {
    print.error(`Failed to initialize: ${(err as Error).message}`);
    process.exit(1);
  }
}

// ============================================================================
// CLI PROGRAM
// ============================================================================

const program = new Command();

program
  .name('jts')
  .description(chalk.cyan('Janus Token System (JTS) CLI'))
  .version(`${VERSION} (JTS Spec ${JTS_SPEC_VERSION})`, '-v, --version')
  .addHelpText('after', `
${chalk.bold('Examples:')}
  ${chalk.dim('# Generate an ES256 key pair')}
  $ jts keygen -a ES256 -o keys/signing-key.pem

  ${chalk.dim('# Inspect a token')}
  $ jts inspect eyJhbGciOiJFUzI1NiIsInR5cCI6Ikp...

  ${chalk.dim('# Verify a token with a public key')}
  $ jts verify <token> --key public-key.pem

  ${chalk.dim('# Convert PEM keys to JWKS')}
  $ jts jwks signing-key.pub.pem -o jwks.json

  ${chalk.dim('# Initialize a new JTS project')}
  $ jts init --profile JTS-S --algorithm ES256 --output ./config
`);

// keygen command
program
  .command('keygen')
  .description('Generate a new key pair for JTS signing')
  .option('-a, --algorithm <alg>', 'Algorithm (RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512)', 'RS256')
  .option('-k, --kid <kid>', 'Key ID (default: auto-generated)')
  .option('-b, --bits <bits>', 'RSA key size in bits (default: 2048)')
  .option('-o, --output <file>', 'Output file for private key')
  .option('-p, --public-out <file>', 'Output file for public key')
  .option('-f, --format <format>', 'Output format: pem or jwk', 'pem')
  .action(keygenCommand);

// inspect command
program
  .command('inspect <token>')
  .description('Decode and display the contents of a JTS token')
  .option('-j, --json', 'Output as JSON')
  .action(inspectCommand);

// verify command
program
  .command('verify <token>')
  .description('Verify the signature of a JTS token')
  .option('-k, --key <file>', 'Public key file (PEM or JWK format)')
  .option('--jwks <url-or-file>', 'JWKS URL or file')
  .action(verifyCommand);

// jwks command
program
  .command('jwks <keyfiles...>')
  .description('Convert key files to JWKS format')
  .option('-o, --output <file>', 'Output file')
  .option('-k, --kid <kid>', 'Key ID (for PEM files)')
  .action(jwksCommand);

// init command
program
  .command('init')
  .description('Initialize JTS configuration for a new project')
  .option('--profile <profile>', 'JTS profile: JTS-L, JTS-S, or JTS-C', 'JTS-S')
  .option('-a, --algorithm <alg>', 'Signing algorithm', 'ES256')
  .option('-o, --output <dir>', 'Output directory', './jts-config')
  .option('-f, --force', 'Overwrite existing directory')
  .action(initCommand);

// Parse arguments
program.parse();

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
