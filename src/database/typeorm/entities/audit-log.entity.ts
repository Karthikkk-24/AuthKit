import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, JoinColumn, Index } from 'typeorm';
import { UserEntity } from './user.entity';

@Entity('audit_logs')
@Index(['userId'])
@Index(['action'])
@Index(['timestamp'])
export class AuditLogEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: true, name: 'user_id' })
  userId: string | null;

  @ManyToOne(() => UserEntity, (u) => u.auditLogs, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'user_id' })
  user: UserEntity | null;

  @Column()
  action: string; // e.g. "auth.login", "user.created"

  @Column({ nullable: true, name: 'resource_id' })
  resourceId: string | null;

  @Column({ nullable: true, name: 'resource_type' })
  resourceType: string | null;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any> | null;

  @Column({ nullable: true })
  ip: string | null;

  @Column({ nullable: true, name: 'user_agent' })
  userAgent: string | null;

  @Column({ default: true })
  success: boolean;

  @CreateDateColumn({ name: 'timestamp' })
  timestamp: Date;
}
