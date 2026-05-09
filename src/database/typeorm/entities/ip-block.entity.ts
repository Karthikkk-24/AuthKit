import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('ip_blocks')
export class IpBlockEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  ip: string;

  @Column({ nullable: true })
  reason: string | null;

  @Column({ nullable: true, name: 'blocked_by_id' })
  blockedById: string | null;

  @Column({ nullable: true, name: 'expires_at' })
  expiresAt: Date | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
