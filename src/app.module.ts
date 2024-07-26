import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';

import { configuration as configVariable, configuration } from '../config/configuration';
import { PerformanceMonitor } from './common/interceptors/performance/performance.interceptor';
import { HttpHandlerModule } from '@josys-src/josys-commons/packages/http';
import { LoggerModule } from '@josys-src/josys-commons/packages/logger';
import { ExampleUseCaseModule } from './applications/examples/example.module';

const dynamicConfig = configVariable()

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      cache: true
    }),
    HttpHandlerModule.forRoot({ timeout: dynamicConfig.HTTP_TIMEOUT }),
    LoggerModule.forRoot({
      appName: dynamicConfig.app.name,
      sentryDNS: dynamicConfig.ERROR_SENTRY_DSN,
      debugMode: dynamicConfig.error.sentry.debug_mode,
      isSentryEnable: dynamicConfig.error.sentry.enable,
      environment: dynamicConfig.NODE_ENV,
      logLevel: [dynamicConfig.ERROR_SENTRY_LOG_LEVEL],
      tracesSampleRate: dynamicConfig.ERROR_SENTRY_TRACES_SAMPLE_RATE
    }),
    ExampleUseCaseModule
  ],
  providers: [
    {
      provide: APP_INTERCEPTOR, useClass: PerformanceMonitor
    },
  ],
})
export class AppModule {}
