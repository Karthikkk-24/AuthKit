import { BadRequestException, ValidationPipe } from '@nestjs/common';
import { UpdateProfileDto } from './update-profile.dto';

describe('UpdateProfileDto (#104)', () => {
  const pipe = new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  });

  const transform = (body: unknown) =>
    pipe.transform(body, {
      type: 'body',
      metatype: UpdateProfileDto,
      data: '',
    });

  it('accepts name and avatarUrl', async () => {
    const result = await transform({
      name: 'Ada',
      avatarUrl: 'https://cdn.example.com/a.png',
    });
    expect(result).toEqual({
      name: 'Ada',
      avatarUrl: 'https://cdn.example.com/a.png',
    });
  });

  it('rejects privileged fields (forbidNonWhitelisted)', async () => {
    await expect(
      transform({
        name: 'Ada',
        roleId: 'superadmin-role',
        isMfaEnabled: false,
        passwordHash: 'x',
        emailVerifiedAt: new Date().toISOString(),
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects non-string name', async () => {
    await expect(transform({ name: 123 })).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });
});
