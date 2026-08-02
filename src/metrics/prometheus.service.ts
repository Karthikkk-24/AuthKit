import { Injectable, OnModuleInit } from '@nestjs/common';
import {
  collectDefaultMetrics,
  Counter,
  Histogram,
  Registry,
} from 'prom-client';

/**
 * Optional Prometheus registry (#54). Default Node metrics plus HTTP
 * counters/histograms when the interceptor records them.
 */
@Injectable()
export class PrometheusService implements OnModuleInit {
  readonly registry = new Registry();
  readonly httpRequests: Counter<string>;
  readonly httpDuration: Histogram<string>;

  constructor() {
    this.httpRequests = new Counter({
      name: 'authkit_http_requests_total',
      help: 'Total HTTP requests',
      labelNames: ['method', 'route', 'status'],
      registers: [this.registry],
    });
    this.httpDuration = new Histogram({
      name: 'authkit_http_request_duration_seconds',
      help: 'HTTP request duration in seconds',
      labelNames: ['method', 'route', 'status'],
      buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
      registers: [this.registry],
    });
  }

  onModuleInit() {
    collectDefaultMetrics({ register: this.registry, prefix: 'authkit_' });
  }

  async metrics(): Promise<string> {
    return this.registry.metrics();
  }
}
