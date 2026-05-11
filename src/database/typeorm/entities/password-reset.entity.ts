import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, JoinColumn, Index } from 'typeorm';
import { UserEntity } from './user.entity';

@Entity('password_resets')
@Index(['userId'])
export class PasswordResetEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id' })
  userId: string;

  @ManyToOne(() => UserEntity, (u) => u.passwordResets, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: UserEntity;

  @Column({ name: 'token_hash', unique: true })
  tokenHash: string;

  @Column({ name: 'expires_at' })
  expiresAt: Date;

  @Column({ nullable: true, name: 'used_at' })
  usedAt: Date | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
