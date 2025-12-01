/**
 * @engjts/auth - Basic Example Server
 * 
 * A complete example showing:
 * - Auth Server setup
 * - Resource Server setup
 * - Express integration with middleware
 * - Login, renewal, and protected routes
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import {
  JTSAuthServer,
  JTSResourceServer,
  generateKeyPair,
  jtsAuth,
  jtsRequirePermissions,
  createJTSRoutes,
  JTSProfile,
} from '../src';

// ============================================================================
// CONFIGURATION
// ============================================================================

const PORT = 3000;
const PROFILE: JTSProfile = 'JTS-S/v1'; // Can be 'JTS-L/v1', 'JTS-S/v1', or 'JTS-C/v1'

// Simulated user database
const USERS: Record<string, { password: string; permissions: string[] }> = {
  'user@example.com': {
    password: 'password123',
    permissions: ['read:profile', 'write:posts'],
  },
  'admin@example.com': {
    password: 'admin123',
    permissions: ['read:profile', 'write:posts', 'admin:users', 'admin:settings'],
  },
};

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  console.log('🚀 Starting JTS Example Server...\n');

  // 1. Generate signing key pair
  console.log('🔑 Generating signing key pair...');
  const signingKey = await generateKeyPair('auth-server-key-2025-001', 'RS256');
  console.log(`   Key ID: ${signingKey.kid}`);
  console.log(`   Algorithm: ${signingKey.algorithm}\n`);

  // 2. Create Auth Server
  console.log('🔐 Creating Auth Server...');
  const authServer = new JTSAuthServer({
    profile: PROFILE,
    signingKey,
    bearerPassLifetime: 300, // 5 minutes
    stateProofLifetime: 7 * 24 * 60 * 60, // 7 days
    gracePeriod: 30,
    rotationGraceWindow: 10,
    sessionPolicy: 'allow_all',
    audience: 'https://api.example.com',
  });
  console.log(`   Profile: ${PROFILE}`);
  console.log(`   BearerPass lifetime: 5 minutes`);
  console.log(`   StateProof lifetime: 7 days\n`);

  // 3. Create Resource Server
  console.log('🛡️  Creating Resource Server...');
  const resourceServer = new JTSResourceServer({
    publicKeys: [signingKey],
    audience: 'https://api.example.com',
    gracePeriodTolerance: 30,
  });
  console.log('   Configured with Auth Server\'s public key\n');

  // 4. Setup Express app
  const app = express();
  app.use(express.json());
  app.use(cookieParser());

  // 5. Setup JTS routes
  const jtsRoutes = createJTSRoutes({
    authServer,
    validateCredentials: async (req) => {
      const { email, password } = req.body;
      
      const user = USERS[email];
      if (!user || user.password !== password) {
        return null;
      }

      return {
        prn: email,
        permissions: user.permissions,
        authMethod: 'pwd',
      };
    },
  });

  // 6. Mount routes
  // Public routes
  app.post('/jts/login', jtsRoutes.loginHandler);
  app.post('/jts/renew', jtsRoutes.renewHandler);
  app.post('/jts/logout', jtsRoutes.logoutHandler);
  app.get('/.well-known/jts-jwks', jtsRoutes.jwksHandler);
  app.get('/.well-known/jts-configuration', jtsRoutes.configHandler);

  // Protected routes
  const authMiddleware = jtsAuth({ resourceServer });
  app.get('/jts/sessions', authMiddleware, jtsRoutes.sessionsHandler);
  app.delete('/jts/sessions/:aid', authMiddleware, jtsRoutes.revokeSessionHandler);

  // 7. Example API routes
  
  // Public route
  app.get('/api/public', (req, res) => {
    res.json({ message: 'This is a public endpoint' });
  });

  // Protected route - requires authentication
  app.get('/api/profile', authMiddleware, (req, res) => {
    res.json({
      message: 'This is your profile',
      user: {
        prn: req.jts!.payload.prn,
        permissions: req.jts!.payload.perm,
        sessionId: req.jts!.payload.aid,
      },
    });
  });

  // Protected route - requires specific permission
  app.get(
    '/api/admin/users',
    authMiddleware,
    jtsRequirePermissions({ required: ['admin:users'] }),
    (req, res) => {
      res.json({
        message: 'Admin users list',
        users: Object.keys(USERS),
      });
    }
  );

  // Protected route - requires any of the permissions
  app.get(
    '/api/posts',
    authMiddleware,
    jtsRequirePermissions({ any: ['read:posts', 'write:posts'] }),
    (req, res) => {
      res.json({
        message: 'Posts list',
        posts: [
          { id: 1, title: 'First post' },
          { id: 2, title: 'Second post' },
        ],
      });
    }
  );

  // 8. Start server
  app.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log(`✅ JTS Example Server running at http://localhost:${PORT}`);
    console.log('='.repeat(60));
    console.log('\n📝 Available endpoints:\n');
    console.log('   Authentication:');
    console.log('   POST /jts/login          - Login and get tokens');
    console.log('   POST /jts/renew          - Renew BearerPass');
    console.log('   POST /jts/logout         - Logout and revoke session');
    console.log('   GET  /jts/sessions       - List active sessions (auth required)');
    console.log('   DELETE /jts/sessions/:aid - Revoke specific session');
    console.log('\n   Discovery:');
    console.log('   GET  /.well-known/jts-jwks          - Public keys (JWKS)');
    console.log('   GET  /.well-known/jts-configuration - Server configuration');
    console.log('\n   API:');
    console.log('   GET  /api/public         - Public endpoint');
    console.log('   GET  /api/profile        - Protected (auth required)');
    console.log('   GET  /api/admin/users    - Protected (admin:users permission)');
    console.log('   GET  /api/posts          - Protected (read/write:posts permission)');
    console.log('\n📋 Test users:');
    console.log('   user@example.com / password123  (regular user)');
    console.log('   admin@example.com / admin123    (admin user)');
    console.log('\n🧪 Example cURL commands:\n');
    console.log('   # Login');
    console.log(`   curl -X POST http://localhost:${PORT}/jts/login \\`);
    console.log('     -H "Content-Type: application/json" \\');
    console.log('     -H "X-JTS-Request: 1" \\');
    console.log('     -d \'{"email":"user@example.com","password":"password123"}\'');
    console.log('\n   # Access protected endpoint');
    console.log(`   curl http://localhost:${PORT}/api/profile \\`);
    console.log('     -H "Authorization: Bearer <YOUR_BEARER_PASS>"');
    console.log('\n');
  });
}

// Run
main().catch(console.error);
