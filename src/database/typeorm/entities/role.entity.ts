import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, OneToMany, JoinColumn } from 'typeorm';
import { UserEntity } from './user.entity';
import { PermissionEntity } from './permission.entity';

@Entity('roles')
export class RoleEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  name: string;

  @Column({ nullable: true })
  description: string | null;

  @Column({ default: false, name: 'is_system' })
  isSystem: boolean;

  @Column({ nullable: true, name: 'parent_id' })
  parentId: string | null;

  @ManyToOne(() => RoleEntity, (role) => role.children, { nullable: true })
  @JoinColumn({ name: 'parent_id' })
  parent: RoleEntity | null;

  @OneToMany(() => RoleEntity, (role) => role.parent)
  children: RoleEntity[];

  @OneToMany(() => PermissionEntity, (p) => p.role)
  permissions: PermissionEntity[];

  @OneToMany(() => UserEntity, (u) => u.role)
  users: UserEntity[];

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
