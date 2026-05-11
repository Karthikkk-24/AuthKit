import {
  IsEmail,
  IsString,
  MinLength,
  MaxLength,
  IsOptional,
  IsBoolean,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({ example: 'john@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'John Doe' })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name: string;

  @ApiProperty({ example: 'Str0ng!Pass' })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  password: string;
}

export class LoginDto {
  @ApiProperty({ example: 'john@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'Str0ng!Pass' })
  @IsString()
  password: string;

  @ApiPropertyOptional({ description: 'TOTP or backup code for MFA' })
  @IsOptional()
  @IsString()
  mfaCode?: string;
}

export class RefreshTokenDto {
  @ApiProperty()
  @IsString()
  refreshToken: string;
}

export class ForgotPasswordDto {
  @ApiProperty({ example: 'john@example.com' })
  @IsEmail()
  email: string;
}

export class ResetPasswordDto {
  @ApiProperty()
  @IsString()
  token: string;

  @ApiProperty({ example: 'NewStr0ng!Pass' })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  newPassword: string;
}

export class ChangePasswordDto {
  @ApiProperty()
  @IsString()
  currentPassword: string;

  @ApiProperty({ example: 'NewStr0ng!Pass' })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  newPassword: string;
}

export class VerifyEmailDto {
  @ApiProperty()
  @IsString()
  token: string;
}

export class MagicLinkRequestDto {
  @ApiProperty({ example: 'john@example.com' })
  @IsEmail()
  email: string;
}

export class VerifyMfaDto {
  @ApiProperty({ description: 'TOTP code or backup code' })
  @IsString()
  code: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  isBackupCode?: boolean;
}
