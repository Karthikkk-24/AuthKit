import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn } from 'typeorm';
import { ResourceEntity } from './resource.entity';

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
