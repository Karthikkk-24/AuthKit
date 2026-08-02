import {
  Controller,
  Post,
  Get,
  Body,
  Query,
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
import { ConfigLoaderService } from '../config/config-loader.service';
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
import { NotFoundException } from '@nestjs/common';
import { Public } from '../common/decorators/public.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { AuthGuard } from '@nestjs/passport';
import type { Request, Response } from 'express';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigLoaderService,
  ) {}

  /** 404 when a strategy/feature is disabled so disabled endpoints look absent. */
  private requireStrategy(
    strategy: 'local' | 'google' | 'github' | 'magicLink' | 'apiKey',
    feature?: 'magicLink' | 'registration' | 'passwordReset',
  ) {
    const strategyOn = this.config.isStrategyEnabled(strategy);
    const featureOn = feature ? this.config.isFeatureEnabled(feature) : true;
    if (!strategyOn && !featureOn) {
      throw new NotFoundException('Not found');
    }
  }

  // ─── REGISTER ──────────────────────────────────────────────────────
  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register a new account' })
  register(@Body() dto: RegisterDto, @Req() req: Request) {
    this.requireStrategy('local', 'registration');
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

  /**
   * GET click-through handler for emailed verification links (#20).
   * Emails cannot POST, so the link targets this handler which verifies
   * the token and redirects the browser to the frontend with a status flag.
   */
  @Public()
  @Get('verify-email')
  @ApiOperation({ summary: 'Verify email via emailed link (redirects to frontend)' })
  async verifyEmailViaLink(@Query('token') token: string, @Res() res: Response) {
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
    try {
      await this.authService.verifyEmail(token);
      res.redirect(`${frontendUrl}/login?verified=1`);
    } catch (err: any) {
      const reason = encodeURIComponent(err?.message || 'invalid_token');
      res.redirect(`${frontendUrl}/login?verified=0&reason=${reason}`);
    }
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
    this.requireStrategy('local');
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
    this.requireStrategy('local', 'passwordReset');
    return this.authService.forgotPassword(dto.email, req);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password using token from email' })
  resetPassword(@Body() dto: ResetPasswordDto, @Req() req: Request) {
    this.requireStrategy('local', 'passwordReset');
    return this.authService.resetPassword(dto, req);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('change-password')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change password (requires current password); revokes other sessions' })
  changePassword(@CurrentUser() user: any, @Body() dto: ChangePasswordDto, @Req() req: Request) {
    return this.authService.changePassword(user.id, dto, req, user.sessionId);
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

  // ─── EMAIL OTP MFA (#18) ────────────────────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Post('mfa/email/send')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Send an email OTP for MFA verification' })
  sendEmailOtp(@CurrentUser() user: any) {
    return this.authService.sendEmailOtp(user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Post('mfa/email/verify')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Verify email OTP and enable email MFA' })
  verifyEmailOtp(@CurrentUser() user: any, @Body() dto: VerifyMfaDto) {
    return this.authService.verifyEmailOtp(user.id, dto.code);
  }

  // ─── MAGIC LINK ────────────────────────────────────────────────────
  @Public()
  @Post('magic-link')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request passwordless magic link login' })
  sendMagicLink(@Body() dto: MagicLinkRequestDto, @Req() req: Request) {
    this.requireStrategy('magicLink', 'magicLink');
    return this.authService.sendMagicLink(dto.email, req);
  }

  @Public()
  @Post('magic-link/verify')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify magic link token and get tokens' })
  verifyMagicLink(@Body() body: { token: string }, @Req() req: Request) {
    this.requireStrategy('magicLink', 'magicLink');
    return this.authService.verifyMagicLink(body.token, req);
  }

  /**
   * GET click-through handler for emailed magic links (#20).
   * Verifies the token, then redirects to the frontend with a one-time
   * exchange code (never raw tokens in a URL — same pattern as OAuth #7).
   */
  @Public()
  @Get('magic-link/verify')
  @ApiOperation({ summary: 'Verify emailed magic link (redirects with one-time code)' })
  async verifyMagicLinkViaLink(
    @Query('token') token: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
    this.requireStrategy('magicLink', 'magicLink');
    try {
      const result: any = await this.authService.verifyMagicLink(token, req);
      // Mint a short-lived one-time code bound to the same user; the frontend
      // exchanges it via POST /auth/oauth/exchange for tokens.
      const code = await this.authService.createOAuthExchangeCode(result.user.id);
      res.redirect(`${frontendUrl}/auth/oauth-success?code=${encodeURIComponent(code)}`);
    } catch (err: any) {
      const reason = encodeURIComponent(err?.message || 'invalid_magic_link');
      res.redirect(`${frontendUrl}/login?magic=0&reason=${reason}`);
    }
  }

  // ─── OAUTH ─────────────────────────────────────────────────────────
  @Public()
  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Initiate Google OAuth flow' })
  googleAuth() {
    this.requireStrategy('google');
    // Passport handles redirect
  }

  @Public()
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Google OAuth callback — redirects with one-time code' })
  async googleCallback(@Req() req: any, @Res() res: Response) {
    const code = await this.authService.createOAuthExchangeCode(req.user.id);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
    // Never put access/refresh tokens in the URL — exchange via POST /auth/oauth/exchange
    res.redirect(`${frontendUrl}/auth/oauth-success?code=${encodeURIComponent(code)}`);
  }

  @Public()
  @Get('github')
  @UseGuards(AuthGuard('github'))
  @ApiOperation({ summary: 'Initiate GitHub OAuth flow' })
  githubAuth() {
    this.requireStrategy('github');
    // Passport handles redirect
  }

  @Public()
  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  @ApiOperation({ summary: 'GitHub OAuth callback — redirects with one-time code' })
  async githubCallback(@Req() req: any, @Res() res: Response) {
    const code = await this.authService.createOAuthExchangeCode(req.user.id);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
    res.redirect(`${frontendUrl}/auth/oauth-success?code=${encodeURIComponent(code)}`);
  }

  @Public()
  @Post('oauth/exchange')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Exchange OAuth one-time code for access and refresh tokens',
  })
  exchangeOAuthCode(@Body() body: { code: string }, @Req() req: Request) {
    return this.authService.exchangeOAuthCode(body.code, req);
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
