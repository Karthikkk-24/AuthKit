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

