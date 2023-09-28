import { Injectable } from '@nestjs/common';
import { HttpExampleService } from 'src/applications/examples/http-example.service';
import { DbexampleService } from './dbexample.service';
import { LogExampleService } from './log-example.service';

@Injectable()
export class ExampleUseCase {
    constructor(
        private readonly httpExampleService: HttpExampleService,
        private readonly dbExampleService: DbexampleService,
        private readonly logExampleService: LogExampleService,
    ) { }

    showHttpUseCase() {
        return this.httpExampleService.getData()
    }

    async showDBUseCase(orgData) {
        return await this.dbExampleService.createOrganisation(orgData)
    }

    showloggerUseCase() {
        return this.logExampleService.getData()
    }
}
