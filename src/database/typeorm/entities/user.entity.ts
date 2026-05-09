import {
  Entity, PrimaryGeneratedColumn, Column, CreateDateColumn,
  UpdateDateColumn, DeleteDateColumn, ManyToOne, OneToMany, JoinColumn,
} from 'typeorm';
import { RoleEntity } from './role.entity';
import { SessionEntity } from './session.entity';
import { ApiKeyEntity } from './api-key.entity';
import { MfaCredentialEntity } from './mfa-credential.entity';
import { AuditLogEntity } from './audit-log.entity';
import { ResourceEntity } from './resource.entity';
import { EmailVerificationEntity } from './email-verification.entity';
import { PasswordResetEntity } from './password-reset.entity';
import { WebhookEntity } from './webhook.entity';

@Entity('users')
export class UserEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true, name: 'email_verified_at' })
  emailVerifiedAt: Date | null;

  @Column({ nullable: true, name: 'password_hash' })
  passwordHash: string | null;

  @Column()
  name: string;

  @Column({ nullable: true, name: 'avatar_url' })
  avatarUrl: string | null;

  @Column({ name: 'role_id' })
  roleId: string;

  @ManyToOne(() => RoleEntity, (role) => role.users)
  @JoinColumn({ name: 'role_id' })
  role: RoleEntity;

  @Column({ default: false, name: 'is_locked' })
  isLocked: boolean;

  @Column({ nullable: true, name: 'locked_at' })
  lockedAt: Date | null;

  @Column({ nullable: true, name: 'lock_reason' })
  lockReason: string | null;

  @Column({ default: 0, name: 'failed_login_attempts' })
  failedLoginAttempts: number;

  @Column({ nullable: true, name: 'last_login_at' })
  lastLoginAt: Date | null;

  @Column({ nullable: true, name: 'last_login_ip' })
  lastLoginIp: string | null;

  @Column({ default: false, name: 'is_mfa_enabled' })
  isMfaEnabled: boolean;

  @Column({ nullable: true, unique: true, name: 'google_id' })
  googleId: string | null;

  @Column({ nullable: true, unique: true, name: 'github_id' })
  githubId: string | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @DeleteDateColumn({ name: 'deleted_at' })
  deletedAt: Date | null;

  @OneToMany(() => SessionEntity, (s) => s.user)
  sessions: SessionEntity[];

  @OneToMany(() => ApiKeyEntity, (k) => k.user)
  apiKeys: ApiKeyEntity[];

  @OneToMany(() => MfaCredentialEntity, (m) => m.user)
  mfaCredentials: MfaCredentialEntity[];

  @OneToMany(() => AuditLogEntity, (a) => a.user)
  auditLogs: AuditLogEntity[];

  @OneToMany(() => ResourceEntity, (r) => r.createdBy)
  resources: ResourceEntity[];

  @OneToMany(() => EmailVerificationEntity, (e) => e.user)
  emailVerifications: EmailVerificationEntity[];

  @OneToMany(() => PasswordResetEntity, (p) => p.user)
  passwordResets: PasswordResetEntity[];

  @OneToMany(() => WebhookEntity, (w) => w.user)
  webhooks: WebhookEntity[];
}
