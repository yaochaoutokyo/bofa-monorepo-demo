import { Permission, Role } from './types';

const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  CUSTOMER: ['account:read', 'transaction:create'],
  TELLER: ['account:read', 'account:write', 'transaction:create', 'pii:view'],
  BRANCH_MANAGER: ['account:read', 'account:write', 'transaction:create', 'transaction:approve', 'pii:view'],
  COMPLIANCE_OFFICER: ['account:read', 'pii:view', 'pii:export', 'audit:read'],
  ADMIN: ['account:read', 'account:write', 'transaction:create', 'transaction:approve', 'pii:view', 'audit:read', 'user:manage'],
};

const ROLE_RANK: Record<Role, number> = {
  CUSTOMER: 0,
  TELLER: 1,
  BRANCH_MANAGER: 2,
  COMPLIANCE_OFFICER: 2,
  ADMIN: 3,
};

/** Pairs of roles that must never be held by the same user (segregation of duties). */
const CONFLICTING_ROLES: Array<[Role, Role]> = [
  ['TELLER', 'COMPLIANCE_OFFICER'],
  ['BRANCH_MANAGER', 'COMPLIANCE_OFFICER'],
];

export function permissionsFor(roles: Role[]): Set<Permission> {
  const permissions = new Set<Permission>();
  for (const role of roles) {
    const granted = ROLE_PERMISSIONS[role];
    if (!granted) {
      throw new Error(`unknown role: ${role}`);
    }
    for (const p of granted) {
      permissions.add(p);
    }
  }
  return permissions;
}

export function hasPermission(roles: Role[], permission: Permission): boolean {
  return permissionsFor(roles).has(permission);
}

export function hasAllPermissions(roles: Role[], required: Permission[]): boolean {
  const granted = permissionsFor(roles);
  return required.every((p) => granted.has(p));
}

export function hasAnyPermission(roles: Role[], candidates: Permission[]): boolean {
  const granted = permissionsFor(roles);
  return candidates.some((p) => granted.has(p));
}

export function highestRole(roles: Role[]): Role | undefined {
  let best: Role | undefined;
  for (const role of roles) {
    if (best === undefined || ROLE_RANK[role] > ROLE_RANK[best]) {
      best = role;
    }
  }
  return best;
}

export function hasConflict(roles: Role[]): [Role, Role] | null {
  const set = new Set(roles);
  for (const [a, b] of CONFLICTING_ROLES) {
    if (set.has(a) && set.has(b)) {
      return [a, b];
    }
  }
  return null;
}

export function canAssignRole(assignerRoles: Role[], targetRole: Role): boolean {
  if (!hasPermission(assignerRoles, 'user:manage')) {
    return false;
  }
  const assignerRank = ROLE_RANK[highestRole(assignerRoles) ?? 'CUSTOMER'];
  return assignerRank >= ROLE_RANK[targetRole];
}

export function canApproveTransaction(approverRoles: Role[], initiatorId: string, approverId: string): boolean {
  if (!hasPermission(approverRoles, 'transaction:approve')) {
    return false;
  }
  return initiatorId !== approverId;
}

export function requiresDualControl(amountCents: number, roles: Role[]): boolean {
  if (amountCents >= 10_000_00) {
    return true;
  }
  if (amountCents >= 5_000_00 && !roles.includes('BRANCH_MANAGER') && !roles.includes('ADMIN')) {
    return true;
  }
  return false;
}

export function effectiveRoles(roles: Role[]): Role[] {
  const unique = Array.from(new Set(roles));
  const conflict = hasConflict(unique);
  if (conflict) {
    throw new Error(`conflicting roles: ${conflict[0]} and ${conflict[1]}`);
  }
  return unique.sort((a, b) => ROLE_RANK[b] - ROLE_RANK[a]);
}

export function describeAccess(roles: Role[]): string {
  const perms = Array.from(permissionsFor(roles)).sort();
  const top = highestRole(roles) ?? 'NONE';
  return `${top}: ${perms.join(', ')}`;
}
