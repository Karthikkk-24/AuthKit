import {
  IsString,
  IsOptional,
  IsBoolean,
  IsUUID,
  IsArray,
  ValidateNested,
  MinLength,
  MaxLength,
  IsIn,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateRoleDto {
  @ApiProperty({ example: 'editor' })
  @IsString()
  @MinLength(2)
  @MaxLength(64)
  name: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(255)
  description?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  parentId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  isSystem?: boolean;
}

export class UpdateRoleDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MinLength(2)
  @MaxLength(64)
  name?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(255)
  description?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  parentId?: string | null;
}

export class CreatePermissionDto {
  @ApiProperty()
  @IsUUID()
  roleId: string;

  @ApiProperty({ example: 'users' })
  @IsString()
  @MinLength(1)
  @MaxLength(64)
  resource: string;

  @ApiProperty({ example: 'read' })
  @IsString()
  @MinLength(1)
  @MaxLength(64)
  action: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(255)
  description?: string;
}

export class PermissionPairDto {
  @ApiProperty({ example: 'read' })
  @IsString()
  @MinLength(1)
  @MaxLength(64)
  action: string;

  @ApiProperty({ example: 'users' })
  @IsString()
  @MinLength(1)
  @MaxLength(64)
  resource: string;
}

export class AssignRolePermissionsDto {
  @ApiProperty({ type: [PermissionPairDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PermissionPairDto)
  permissions: PermissionPairDto[];
}

export class UserPermissionOverrideDto {
  @ApiProperty({ example: 'read' })
  @IsString()
  @MinLength(1)
  @MaxLength(64)
  action: string;

  @ApiProperty({ example: 'users' })
  @IsString()
  @MinLength(1)
  @MaxLength(64)
  resource: string;

  @ApiProperty({ enum: ['grant', 'deny'] })
  @IsIn(['grant', 'deny'])
  effect: 'grant' | 'deny';
}

export class SetUserPermissionsDto {
  @ApiProperty({ type: [UserPermissionOverrideDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => UserPermissionOverrideDto)
  permissions: UserPermissionOverrideDto[];
}
