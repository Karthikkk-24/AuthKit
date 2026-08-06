import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, VersioningType, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import helmet from 'helmet';
import compression from 'compression';
import { ConfigLoaderService } from './config/config-loader.service';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, {
    logger: ['log', 'warn', 'error', 'debug', 'verbose'],
  });

  const config = app.get(ConfigLoaderService);
  const port = process.env.PORT ?? 3000;
  const nodeEnv = process.env.NODE_ENV ?? 'development';

  // ── Trust proxy (#96) ─────────────────────────────────────────────
  // Enable when behind Nginx/ALB/Cloudflare so req.ip reflects the client.
  // Do NOT enable without a real proxy — clients can spoof X-Forwarded-For.
  const trustProxy = process.env.TRUST_PROXY;
  const httpApp = app.getHttpAdapter().getInstance();
  if (trustProxy === 'true' || trustProxy === '1') {
    httpApp.set('trust proxy', 1);
    logger.log('trust proxy enabled (1 hop)');
  } else if (trustProxy && /^\d+$/.test(trustProxy)) {
    httpApp.set('trust proxy', parseInt(trustProxy, 10));
    logger.log(`trust proxy enabled (${trustProxy} hops)`);
  }

  // ── Security ──────────────────────────────────────────────────────
  app.use(helmet());
  app.use(compression());

  // ── CORS (#77) ────────────────────────────────────────────────────
  const corsConfig = config.get<any>('security')?.cors ?? {};
  const origins: string[] = Array.isArray(corsConfig.origins)
    ? corsConfig.origins.filter((o: unknown) => typeof o === 'string' && o && o !== '*')
    : [];
  const wantCredentials = corsConfig.credentials !== false;

  if (nodeEnv === 'production' && origins.length === 0) {
    throw new Error(
      'security.cors.origins must be a non-empty list in production (never * with credentials)',
    );
  }

  if (origins.length > 0) {
    app.enableCors({
      origin: origins,
      credentials: wantCredentials,
      methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    });
  } else {
    // Dev-only: reflect request Origin (never bare *)
    app.enableCors({
      origin: true,
      credentials: true,
      methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    });
  }

  // ── Global prefix & versioning ────────────────────────────────────
  app.setGlobalPrefix('api');
  app.enableVersioning({ type: VersioningType.URI, defaultVersion: '1' });

  // ── Validation ────────────────────────────────────────────────────
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  // ── Swagger (non-production) ──────────────────────────────────────
  if (nodeEnv !== 'production') {
    const swaggerConfig = new DocumentBuilder()
      .setTitle('AuthKit API')
      .setDescription(
        'Enterprise-grade Authentication & Authorization Platform — Plug & Play',
      )
      .setVersion('1.0')
      .addBearerAuth()
      .addApiKey({ type: 'apiKey', name: 'X-API-Key', in: 'header' }, 'api-key')
      .addServer(`http://localhost:${port}`, 'Local')
      .build();

    const document = SwaggerModule.createDocument(app, swaggerConfig);
    SwaggerModule.setup('docs', app, document, {
      swaggerOptions: { persistAuthorization: true },
    });

    logger.log(`📚 Swagger: http://localhost:${port}/docs`);
  }

  await app.listen(port);
  logger.log(`🚀 AuthKit API running on port ${port} [${nodeEnv}]`);
}

bootstrap();
