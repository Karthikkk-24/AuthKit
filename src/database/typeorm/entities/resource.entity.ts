import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, OneToMany, JoinColumn } from 'typeorm';
import { UserEntity } from './user.entity';
import { ResourceAccessEntity } from './resource-access.entity';

@Entity('resources')
export class ResourceEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  title: string;

  @Column({ nullable: true })
  content: string | null;

  @Column({ name: 'created_by_id' })
  createdById: string;

  @ManyToOne(() => UserEntity, (u) => u.resources)
  @JoinColumn({ name: 'created_by_id' })
  createdBy: UserEntity;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @OneToMany(() => ResourceAccessEntity, (ra) => ra.resource)
  resourceAccesses: ResourceAccessEntity[];
}

@Entity('resource_accesses')
export class ResourceAccessEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'resource_id' })
  resourceId: string;

  @ManyToOne(() => ResourceEntity, (r) => r.resourceAccesses, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'resource_id' })
  resource: ResourceEntity;

  @Column({ nullable: true, name: 'user_id' })
  userId: string | null;

  @Column({ nullable: true, name: 'role_id' })
  roleId: string | null;

  @Column({ default: false, name: 'can_read' })
  canRead: boolean;

  @Column({ default: false, name: 'can_write' })
  canWrite: boolean;

  @Column({ default: false, name: 'can_delete' })
  canDelete: boolean;
}
