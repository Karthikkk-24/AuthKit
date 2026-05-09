import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, JoinColumn, Unique } from 'typeorm';
import { UserEntity } from './user.entity';

export enum MfaType { TOTP = 'TOTP', EMAIL = 'EMAIL', SMS = 'SMS' }

@Entity('mfa_credentials')
@Unique(['userId', 'type'])
export class MfaCredentialEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id' })
  userId: string;

  @ManyToOne(() => UserEntity, (u) => u.mfaCredentials, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: UserEntity;

  @Column({ type: 'enum', enum: MfaType })
  type: MfaType;

  @Column({ nullable: true })
  secret: string | null;

  @Column({ default: false, name: 'is_enabled' })
  isEnabled: boolean;

  @Column('simple-array', { default: '', name: 'backup_codes' })
  backupCodes: string[];

  @Column({ nullable: true, name: 'verified_at' })
  verifiedAt: Date | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
