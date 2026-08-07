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

/** Begin TOTP enrollment / re-enrollment (#125). */
export class SetupTotpDto {
  @ApiPropertyOptional({
    description:
      'Required when MFA is already enabled — prove the current factor before rotating the TOTP secret',
  })
  @IsOptional()
  @IsString()
  currentMfaCode?: string;
}

export class ExchangeOAuthCodeDto {
  @ApiProperty({ description: 'One-time OAuth / magic-link exchange code' })
  @IsString()
  code: string;

  @ApiPropertyOptional({ description: 'TOTP / email OTP / backup code when MFA is enrolled' })
  @IsOptional()
  @IsString()
  mfaCode?: string;
}

export class CompleteMfaLoginDto {
  @ApiProperty({ description: 'One-time MFA challenge token from OAuth/magic-link' })
  @IsString()
  mfaToken: string;

  @ApiProperty({ description: 'TOTP / email OTP / backup code' })
  @IsString()
  mfaCode: string;
}

/** Request an email OTP during an unauthenticated MFA login challenge (#106). */
export class MfaChallengeEmailDto {
  @ApiProperty({
    description:
      'One-time mfaToken from login / OAuth / magic-link MFA challenge (proves first factor)',
  })
  @IsString()
  mfaToken: string;
}

export class VerifyMagicLinkDto {
  @ApiProperty()
  @IsString()
  token: string;

  @ApiPropertyOptional({ description: 'TOTP / email OTP / backup code when MFA is enrolled' })
  @IsOptional()
  @IsString()
  mfaCode?: string;
}

export class DisableMfaDto {
  @ApiPropertyOptional({ description: 'Required for password accounts' })
  @IsOptional()
  @IsString()
  password?: string;

  @ApiPropertyOptional({
    description:
      'Required for OAuth-only / passwordless accounts (TOTP, email OTP, or backup code)',
  })
  @IsOptional()
  @IsString()
  mfaCode?: string;
}
