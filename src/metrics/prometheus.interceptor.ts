import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable, tap } from 'rxjs';
import { PrometheusService } from '../metrics/prometheus.service';

@Injectable()
export class PrometheusInterceptor implements NestInterceptor {
  constructor(private readonly prom: PrometheusService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (context.getType() !== 'http') return next.handle();
    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();
    const start = process.hrtime.bigint();
    const route = req.route?.path ?? req.path ?? 'unknown';
    const method = req.method ?? 'GET';

    return next.handle().pipe(
      tap({
        next: () => this.observe(method, route, res.statusCode ?? 200, start),
        error: (err) =>
          this.observe(method, route, err?.status ?? err?.statusCode ?? 500, start),
      }),
    );
  }

  private observe(method: string, route: string, status: number, start: bigint) {
    const seconds = Number(process.hrtime.bigint() - start) / 1e9;
    const labels = { method, route, status: String(status) };
    this.prom.httpRequests.inc(labels);
    this.prom.httpDuration.observe(labels, seconds);
  }
}
