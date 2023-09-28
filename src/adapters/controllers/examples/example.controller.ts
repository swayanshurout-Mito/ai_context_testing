import { Body, Controller, Get, Post } from '@nestjs/common';
import { Organization as OrganizationModel } from '@prisma/mysql/client';
import { DbexampleService } from 'src/applications/examples/dbexample.service';
import { HttpExampleService } from 'src/applications/examples/http-example.service';
import { LogExampleService } from 'src/applications/examples/log-example.service';

@Controller()
export class ExampleController {

    constructor(
        private readonly dbService: DbexampleService,
        private readonly httpExampleService: HttpExampleService,
        private readonly logExampleService: LogExampleService
        ) {}

    @Get('http-example')
    fetchData() {
        return this.httpExampleService.getData();
    }

    @Get('logger-example')
    displayLogData() {
        return this.logExampleService.getData();
    }
    
    @Post('organisation')
    async addOrganisation(
      @Body() userData: { id?: BigInt, display_name?: string }
    ): Promise<OrganizationModel> {
      return this.dbService.createOrganisation(userData);
    }
}
