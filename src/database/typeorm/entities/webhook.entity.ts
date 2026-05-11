import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, OneToMany, JoinColumn } from 'typeorm';
import { UserEntity } from './user.entity';

@Entity('webhooks')
export class WebhookEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id' })
  userId: string;

  @ManyToOne(() => UserEntity, (u) => u.webhooks, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: UserEntity;

  @Column()
  url: string;

  @Column()
  secret: string;

  @Column('simple-array')
  events: string[];

  @Column({ default: true, name: 'is_active' })
  isActive: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @OneToMany(() => WebhookDeliveryEntity, (d) => d.webhook)
  deliveries: WebhookDeliveryEntity[];
}

@Entity('webhook_deliveries')
export class WebhookDeliveryEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'webhook_id' })
  webhookId: string;

  @ManyToOne(() => WebhookEntity, (w) => w.deliveries, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'webhook_id' })
  webhook: WebhookEntity;

  @Column()
  event: string;

  @Column({ type: 'jsonb' })
  payload: Record<string, any>;

  @Column({ nullable: true, name: 'status_code' })
  statusCode: number | null;

  @Column({ nullable: true, name: 'response_body' })
  responseBody: string | null;

  @Column({ default: 0 })
  attempts: number;

  @Column({ default: false })
  success: boolean;

  @Column({ nullable: true, name: 'next_retry_at' })
  nextRetryAt: Date | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
