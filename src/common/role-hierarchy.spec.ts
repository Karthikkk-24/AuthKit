import {
  assertActorOutranksTarget,
  getRoleRank,
  permissionCovers,
  permissionsSubsetOf,
} from './role-hierarchy';
import { ForbiddenException } from '@nestjs/common';

describe('role-hierarchy helpers', () => {
  it('ranks roles correctly', () => {
    expect(getRoleRank('guest')).toBe(0);
    expect(getRoleRank('superadmin')).toBe(4);
    expect(getRoleRank('unknown')).toBe(-1);
  });

  it('assertActorOutranksTarget allows admin over user', () => {
    expect(() =>
      assertActorOutranksTarget('admin', 'user', 'lock'),
    ).not.toThrow();
  });

  it('assertActorOutranksTarget blocks admin over superadmin', () => {
    expect(() =>
      assertActorOutranksTarget('admin', 'superadmin', 'lock'),
    ).toThrow(ForbiddenException);
  });

  it('assertActorOutranksTarget blocks peer admin', () => {
    expect(() =>
      assertActorOutranksTarget('admin', 'admin', 'lock'),
    ).toThrow(ForbiddenException);
  });

  it('assertActorOutranksTarget allows admin to manage custom-role users', () => {
    expect(() =>
      assertActorOutranksTarget('admin', 'editor', 'lock'),
    ).not.toThrow();
  });

  it('assertActorOutranksTarget blocks moderator from managing custom-role users', () => {
    expect(() =>
      assertActorOutranksTarget('moderator', 'editor', 'lock'),
    ).toThrow(ForbiddenException);
  });

  it('permissionCovers handles wildcards', () => {
    expect(
      permissionCovers([{ action: '*', resource: '*' }], {
        action: 'delete',
        resource: 'users',
      }),
    ).toBe(true);
    expect(
      permissionCovers([{ action: 'read', resource: 'users' }], {
        action: 'delete',
        resource: 'users',
      }),
    ).toBe(false);
  });

  it('permissionsSubsetOf requires full coverage', () => {
    const held = [
      { action: 'read', resource: 'users' },
      { action: 'update', resource: 'users' },
    ];
    expect(
      permissionsSubsetOf([{ action: 'read', resource: 'users' }], held),
    ).toBe(true);
    expect(
      permissionsSubsetOf([{ action: '*', resource: '*' }], held),
    ).toBe(false);
  });
});
