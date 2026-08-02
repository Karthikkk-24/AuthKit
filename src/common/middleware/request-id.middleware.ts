import { Injectable, NestMiddleware } from '@nestjs/common';
import { randomUUID } from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { requestContext } from '../request-context';

/**
 * Assigns/propagates X-Request-Id and stores it in AsyncLocalStorage so
 * audit logs and handlers can correlate without threading req everywhere (#54).
 */
@Injectable()
export class RequestIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const incoming = req.header('x-request-id');
    const requestId =
      incoming && incoming.trim().length > 0 ? incoming.trim().slice(0, 128) : randomUUID();

    res.setHeader('X-Request-Id', requestId);
    (req as any).requestId = requestId;

    requestContext.run({ requestId }, () => next());
  }
}
