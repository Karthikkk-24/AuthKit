import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn, Unique } from 'typeorm';
import { RoleEntity } from './role.entity';

@Entity('permissions')
@Unique(['action', 'resource', 'roleId'])
export class PermissionEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  action: string; // "read" | "write" | "delete" | "*"

  @Column()
  resource: string; // "user" | "post" | "*"

  @Column({ name: 'role_id' })
  roleId: string;

  @ManyToOne(() => RoleEntity, (r) => r.permissions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'role_id' })
  role: RoleEntity;
}
