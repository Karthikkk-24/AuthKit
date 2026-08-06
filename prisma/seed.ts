/**
 * AuthKit Database Seed
 * Run: npx ts-node prisma/seed.ts
 *
 * Creates:
 *  - 5 system roles (superadmin, admin, moderator, user, guest)
 *  - Full permission set across all resources
 *  - Default superadmin account (change password immediately!)
 */

import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

// ── Resources + actions ──────────────────────────────────────────────
const PERMISSIONS: Array<{ resource: string; action: string; description?: string }> = [
  // Users
  { resource: 'users', action: 'create',  description: 'Create new users' },
  { resource: 'users', action: 'read',    description: 'View user profiles' },
  { resource: 'users', action: 'update',  description: 'Update user profiles' },
  { resource: 'users', action: 'delete',  description: 'Delete / soft-delete users' },
  { resource: 'users', action: 'lock',    description: 'Lock / unlock accounts' },
  { resource: 'users', action: '*',       description: 'Full user access (wildcard)' },
  // Sessions
  { resource: 'sessions', action: 'read',   description: 'View sessions' },
  { resource: 'sessions', action: 'revoke', description: 'Revoke sessions' },
  { resource: 'sessions', action: '*',      description: 'Full session access' },
  // Roles & Permissions
  { resource: 'roles',       action: 'create', description: 'Create roles' },
  { resource: 'roles',       action: 'read',   description: 'View roles' },
  { resource: 'roles',       action: 'update', description: 'Update roles' },
  { resource: 'roles',       action: 'delete', description: 'Delete roles' },
  { resource: 'roles',       action: '*',      description: 'Full role access' },
  { resource: 'permissions', action: 'create', description: 'Create permissions' },
  { resource: 'permissions', action: 'read',   description: 'View permissions' },
  { resource: 'permissions', action: 'update', description: 'Update permission overrides' },
  { resource: 'permissions', action: 'delete', description: 'Delete permissions' },
  { resource: 'permissions', action: '*',      description: 'Full permission access' },
  // Audit
  { resource: 'audit', action: 'read',   description: 'View audit logs' },
  { resource: 'audit', action: 'export', description: 'Export audit logs' },
  { resource: 'audit', action: '*',      description: 'Full audit access' },
  // Webhooks
  { resource: 'webhooks', action: 'create', description: 'Register webhooks' },
  { resource: 'webhooks', action: 'read',   description: 'View webhooks' },
  { resource: 'webhooks', action: 'update', description: 'Update webhooks' },
  { resource: 'webhooks', action: 'delete', description: 'Delete webhooks' },
  { resource: 'webhooks', action: '*',      description: 'Full webhook access' },
  // API Keys
  { resource: 'apikeys', action: 'create', description: 'Create API keys' },
  { resource: 'apikeys', action: 'read',   description: 'View API keys' },
  { resource: 'apikeys', action: 'revoke', description: 'Revoke API keys' },
  { resource: 'apikeys', action: '*',      description: 'Full API key access' },
  // MFA
  { resource: 'mfa', action: 'enroll',  description: 'Enroll MFA' },
  { resource: 'mfa', action: 'disable', description: 'Disable MFA' },
  { resource: 'mfa', action: '*',       description: 'Full MFA access' },
  // Metrics
  { resource: 'metrics', action: 'read', description: 'View platform metrics' },
  // Settings / config (#29)
  { resource: 'settings', action: 'read', description: 'View platform settings' },
  { resource: 'settings', action: 'update', description: 'Update platform settings' },
  { resource: 'settings', action: '*', description: 'Full settings access' },
];

// ── Role permission grants ────────────────────────────────────────────
const ROLE_PERMISSIONS: Record<string, string[]> = {
  superadmin: ['*:*'],  // resolved by wildcard engine — grant all
  admin: [
    'users:*', 'sessions:*', 'roles:read', 'roles:update',
    'permissions:read', 'permissions:create', 'permissions:update',
    'audit:*', 'webhooks:*', 'apikeys:*',
    'mfa:*', 'metrics:read', 'settings:*',
  ],
  moderator: [
    'users:read', 'users:lock', 'sessions:read', 'sessions:revoke',
    'audit:read', 'mfa:*',
  ],
  user: [
    'users:read', 'sessions:read', 'sessions:revoke',
    'apikeys:create', 'apikeys:read', 'apikeys:revoke',
    'mfa:enroll', 'mfa:disable',
  ],
  guest: ['users:read'],
};

async function main() {
  console.log('🌱 Seeding AuthKit database…\n');

  // 1. Create roles
  console.log('  → Creating system roles…');
  const roleHierarchy = [
    { name: 'guest',      description: 'Unauthenticated / minimal access' },
    { name: 'user',       description: 'Standard authenticated user', parentName: 'guest' },
    { name: 'moderator',  description: 'Content & user moderation', parentName: 'user' },
    { name: 'admin',      description: 'Platform administration', parentName: 'moderator' },
    { name: 'superadmin', description: 'Full unrestricted access', parentName: 'admin' },
  ];

  const roleIds: Record<string, string> = {};

  for (const role of roleHierarchy) {
    const parentId = role.parentName ? roleIds[role.parentName] : undefined;
    const r = await prisma.role.upsert({
      where: { name: role.name },
      update: { description: role.description },
      create: {
        name: role.name,
        description: role.description,
        isSystem: true,
        parentId,
      },
    });
    roleIds[role.name] = r.id;
  }
  console.log(`     ✔ ${roleHierarchy.length} roles`);

  // 2. Assign permissions to roles
  console.log('  → Assigning permissions to roles…');
  for (const [roleName, grants] of Object.entries(ROLE_PERMISSIONS)) {
    const roleId = roleIds[roleName];
    if (!roleId) continue;

    // Expand wildcards based on PERMISSIONS array
    const permsToCreate: Array<{ resource: string; action: string }> = [];
    for (const grant of grants) {
      if (grant === '*:*') {
        // Superadmin: all permissions
        PERMISSIONS.forEach(p => permsToCreate.push({ resource: p.resource, action: p.action }));
      } else {
        const [resource, action] = grant.split(':');
        permsToCreate.push({ resource, action });
      }
    }

    // Deduplicate and upsert
    for (const perm of permsToCreate) {
      await prisma.permission.upsert({
        where: {
          action_resource_roleId: {
            action: perm.action,
            resource: perm.resource,
            roleId: roleId,
          }
        },
        update: {},
        create: {
          action: perm.action,
          resource: perm.resource,
          roleId: roleId,
        }
      });
    }
  }
  console.log('     ✔ Permissions assigned');

  // 3. Superadmin user
  console.log('  → Creating default superadmin…');
  const superadminEmail = process.env.SEED_ADMIN_EMAIL ?? 'admin@authkit.dev';
  const defaultPublishedPassword = 'Admin@AuthKit2025!';
  const superadminPassword = process.env.SEED_ADMIN_PASSWORD ?? defaultPublishedPassword;
  const isProd = process.env.NODE_ENV === 'production';

  if (isProd) {
    if (!process.env.SEED_ADMIN_PASSWORD) {
      throw new Error(
        'SEED_ADMIN_PASSWORD is required when seeding in production. ' +
          'Do not use the published default password.',
      );
    }
    if (superadminPassword === defaultPublishedPassword) {
      throw new Error(
        'Refusing to seed production with the published default SEED_ADMIN_PASSWORD. ' +
          'Choose a unique strong password.',
      );
    }
  } else if (
    !process.env.SEED_ADMIN_PASSWORD ||
    superadminPassword === defaultPublishedPassword
  ) {
    console.warn(
      '     ⚠  Using published default admin password — set SEED_ADMIN_PASSWORD before any shared/prod deploy.',
    );
  }

  const passwordHash = await argon2.hash(superadminPassword, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });

  await prisma.user.upsert({
    where: { email: superadminEmail },
    update: {},
    create: {
      email: superadminEmail,
      name: 'Super Admin',
      passwordHash,
      emailVerifiedAt: new Date(),
      roleId: roleIds['superadmin'],
    },
  });

  console.log(`     ✔ Superadmin: ${superadminEmail}`);
  if (!isProd) {
    console.log(`     ⚠  Change the default password immediately if this is not a throwaway local DB.\n`);
  }
  console.log('✅ Seed complete!');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
