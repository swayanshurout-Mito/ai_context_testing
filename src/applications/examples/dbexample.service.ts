import { Injectable } from '@nestjs/common';
import { ExampleDBRepository } from 'src/adapters/persistence/repositories/examples/db.repository';

@Injectable()
export class DbexampleService {
    constructor(
        private readonly exampleExternalApiService: ExampleDBRepository
    ) { }

    async createOrganisation(orgData): Promise<any> {
        // const result = await this.mongo.organization.create({
        //     data: orgData
        // });
        const mysqlResult = await this.exampleExternalApiService.addOrganisationToMysqlDB(orgData)
        return mysqlResult;
    }
}
