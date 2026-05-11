import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, JoinColumn, Index } from 'typeorm';
import { UserEntity } from './user.entity';

@Entity('sessions')
@Index(['userId'])
export class SessionEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id' })
  userId: string;

  @ManyToOne(() => UserEntity, (u) => u.sessions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: UserEntity;

  @Column({ name: 'refresh_token_hash' })
  refreshTokenHash: string;

  @Column({ default: false, name: 'is_revoked' })
  isRevoked: boolean;

  @Column({ nullable: true, name: 'revoked_at' })
  revokedAt: Date | null;

  @Column({ nullable: true })
  ip: string | null;

  @Column({ nullable: true, name: 'user_agent' })
  userAgent: string | null;

  @Column({ nullable: true, name: 'device_name' })
  deviceName: string | null;

  @Column({ nullable: true, name: 'device_type' })
  deviceType: string | null;

  @Column({ nullable: true })
  browser: string | null;

  @Column({ nullable: true })
  os: string | null;

  @Column({ nullable: true })
  country: string | null;

  @Column({ nullable: true })
  city: string | null;

  @Column({ name: 'last_active_at', type: 'timestamptz', default: () => 'NOW()' })
  lastActiveAt: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;
}
