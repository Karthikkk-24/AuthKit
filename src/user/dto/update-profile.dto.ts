import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

/**
 * Whitelisted self-service profile fields only (#104).
 * Global ValidationPipe (whitelist + forbidNonWhitelisted) strips/rejects
 * anything else — never pass the raw body into Prisma.
 */
export class UpdateProfileDto {
  @ApiPropertyOptional({ example: 'Jane Doe' })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  name?: string;

  @ApiPropertyOptional({ example: 'https://cdn.example.com/avatar.png' })
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  avatarUrl?: string;
}
