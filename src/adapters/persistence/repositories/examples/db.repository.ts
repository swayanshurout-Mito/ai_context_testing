import { Injectable } from '@nestjs/common';
import { ExampleDAO } from '../../prisma/dao/example.dao';

@Injectable()
export class ExampleDBRepository {
    constructor(
        private readonly exampleDAO: ExampleDAO,
    ) { }
    async addOrganisationToMysqlDB(auditLog: any): Promise<void> {
        return await this.exampleDAO.addOrganisationInMysqlDB(auditLog)
    }
}
