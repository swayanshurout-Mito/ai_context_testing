import { Module } from '@nestjs/common';
import { ExampleController } from 'src/adapters/controllers/examples/example.controller';
import { ExampleUseCase } from './examples.use-case';
import { HttpExampleService } from './http-example.service';
import { DbexampleService } from './dbexample.service';
import { LogExampleService } from './log-example.service';
import { WebModule } from 'src/adapters/web/web.module';
import { RepositoryModule } from 'src/adapters/persistence/repositories.module';


@Module({
  imports: [
    RepositoryModule,
    WebModule,
  ],
  controllers: [ExampleController],
  providers: [
    //--------Use cases------//
    DbexampleService,
    ExampleUseCase,
    HttpExampleService,
    LogExampleService,
  ],
  exports: [
    ExampleUseCase,
  ]
})
export class ExampleUseCaseModule { }
