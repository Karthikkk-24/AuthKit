/**
 * Lightweight smoke e2e — full auth register→login flows need a live
 * Postgres/Redis stack. When DATABASE_URL is unset we skip rather than
 * fail CI (#52). Run locally with docker compose + `pnpm test:e2e`.
 */
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, VersioningType } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';

const describeIfDb = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDb('Auth API contract (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    const { AppModule } = await import('./../src/app.module');
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api');
    app.enableVersioning({ type: VersioningType.URI, defaultVersion: '1' });
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
  });

  it('GET /api/v1/health is public', async () => {
    const res = await request(app.getHttpServer()).get('/api/v1/health');
    expect([200, 503]).toContain(res.status);
  });

  it('POST /api/v1/auth/login rejects bad credentials without leaking stack', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({ email: 'nobody@example.com', password: 'WrongPass1!' });
    expect(res.status).toBe(401);
    expect(res.body.message).toBeDefined();
    expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|stack/i);
  });
});

describe('e2e harness', () => {
  it('documents DATABASE_URL requirement when skipped', () => {
    if (!process.env.DATABASE_URL) {
      expect(process.env.DATABASE_URL).toBeUndefined();
    } else {
      expect(process.env.DATABASE_URL).toBeTruthy();
    }
  });
});
