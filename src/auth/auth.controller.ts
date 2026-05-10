import {
  Controller,
  Post,
  Get,
  Body,
  Req,
  Res,
  UseGuards,
  Delete,
  Patch,
  Param,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import {
  RegisterDto,
  LoginDto,
  RefreshTokenDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  ChangePasswordDto,
  VerifyEmailDto,
  MagicLinkRequestDto,
  VerifyMfaDto,
} from './dto/auth.dto';
import { Public } from '../common/decorators/public.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { AuthGuard } from '@nestjs/passport';
import type { Request, Response } from 'express';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ─── REGISTER ──────────────────────────────────────────────────────
  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register a new account' })
  register(@Body() dto: RegisterDto, @Req() req: Request) {
    return this.authService.register(dto, req);
  }

  // ─── EMAIL VERIFICATION ────────────────────────────────────────────
  @Public()
  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify email address with token' })
  verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.authService.verifyEmail(dto.token);
  }

  @UseGuards(JwtAuthGuard)
  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Resend email verification link' })
  resendVerification(@CurrentUser() user: any) {
    return this.authService.sendEmailVerification(user.id);
  }

  // ─── LOGIN ─────────────────────────────────────────────────────────
  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login with email + password' })
  async login(@Body() dto: LoginDto, @Req() req: Request) {
    const user = await this.authService.validateLocalUser(dto.email, dto.password);
    if (!user) throw new UnauthorizedException('Invalid credentials');
    return this.authService.login(user, dto, req);
  }

  // ─── REFRESH TOKEN ─────────────────────────────────────────────────
  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token using refresh token' })
  refresh(@Body() dto: RefreshTokenDto, @Req() req: Request) {
    return this.authService.refreshTokens(dto.refreshToken, req);
  }

  // ─── LOGOUT ────────────────────────────────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout from current device' })
  logout(@CurrentUser() user: any, @Req() req: Request) {
    const token = req.headers?.['authorization']?.replace('Bearer ', '') || '';
    return this.authService.logout(user.id, user.sessionId, token, req);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout from all devices' })
  logoutAll(@CurrentUser() user: any, @Req() req: Request) {
    const token = req.headers?.['authorization']?.replace('Bearer ', '') || '';
    return this.authService.logoutAll(user.id, token, req);
  }

  // ─── PASSWORD ──────────────────────────────────────────────────────
  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request a password reset email' })
  forgotPassword(@Body() dto: ForgotPasswordDto, @Req() req: Request) {
    return this.authService.forgotPassword(dto.email, req);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password using token from email' })
  resetPassword(@Body() dto: ResetPasswordDto, @Req() req: Request) {
    return this.authService.resetPassword(dto, req);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('change-password')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change password (requires current password)' })
  changePassword(@CurrentUser() user: any, @Body() dto: ChangePasswordDto, @Req() req: Request) {
    return this.authService.changePassword(user.id, dto, req);
  }

  // ─── MFA ───────────────────────────────────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Post('mfa/totp/setup')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Generate TOTP secret and QR code' })
  setupTotp(@CurrentUser() user: any) {
    return this.authService.setupTotp(user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Post('mfa/totp/enable')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Confirm TOTP setup and get backup codes' })
  enableTotp(@CurrentUser() user: any, @Body() dto: VerifyMfaDto) {
    return this.authService.enableTotp(user.id, dto.code);
  }

  @UseGuards(JwtAuthGuard)
  @Delete('mfa/disable')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Disable MFA (requires password confirmation)' })
  disableMfa(@CurrentUser() user: any, @Body() body: { password: string }) {
    return this.authService.disableMfa(user.id, body.password);
  }

  // ─── MAGIC LINK ────────────────────────────────────────────────────
  @Public()
  @Post('magic-link')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request passwordless magic link login' })
  sendMagicLink(@Body() dto: MagicLinkRequestDto, @Req() req: Request) {
    return this.authService.sendMagicLink(dto.email, req);
  }

  @Public()
  @Post('magic-link/verify')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify magic link token and get tokens' })
  verifyMagicLink(@Body() body: { token: string }, @Req() req: Request) {
    return this.authService.verifyMagicLink(body.token, req);
  }

  // ─── OAUTH ─────────────────────────────────────────────────────────
  @Public()
  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Initiate Google OAuth flow' })
  googleAuth() {
    // Passport handles redirect
  }

  @Public()
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Google OAuth callback' })
  async googleCallback(@Req() req: any, @Res() res: Response) {
    const tokens = await this.authService.createTokens(req.user, req);
    // Redirect to frontend with tokens
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
    res.redirect(
      `${frontendUrl}/auth/oauth-success?token=${tokens.accessToken}&refresh=${tokens.refreshToken}`,
    );
  }

  @Public()
  @Get('github')
  @UseGuards(AuthGuard('github'))
  @ApiOperation({ summary: 'Initiate GitHub OAuth flow' })
  githubAuth() {
    // Passport handles redirect
  }

  @Public()
  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  @ApiOperation({ summary: 'GitHub OAuth callback' })
  async githubCallback(@Req() req: any, @Res() res: Response) {
    const tokens = await this.authService.createTokens(req.user, req);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
    res.redirect(
      `${frontendUrl}/auth/oauth-success?token=${tokens.accessToken}&refresh=${tokens.refreshToken}`,
    );
  }

  // ─── ME ────────────────────────────────────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current authenticated user' })
  getMe(@CurrentUser() user: any) {
    return user;
  }
}
