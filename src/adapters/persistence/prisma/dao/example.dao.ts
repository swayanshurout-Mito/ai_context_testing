import { Injectable } from '@nestjs/common';
import { LoggerService } from '@josys-src/josys-commons/packages/logger';
import { MongoService } from '../service/mongo.service';
import { MysqlService } from '../service/mysql.service';

@Injectable()
export class ExampleDAO {
    constructor(
        private readonly mongo: MongoService,
        private readonly mysql: MysqlService,
        private readonly loggerService: LoggerService
    ) { }

    async  addOrganisationInMysqlDB(collections: any): Promise<void> {
        try {
            const createdSoftwareLookup = await this.mysql.organization.create({
                data: collections,
                select: {
                    id: true,
                },
            });
        } catch (error) {
            this.loggerService.unKnownExecption(error)
        }
    }

    async  addOrganisationInMongoDB(collections: any): Promise<void> {
        try {
            await this.mongo.organization.create({
                data: collections,
                select: {
                    id: true,
                },
            });
        } catch (error) {
            this.loggerService.unKnownExecption(error)
        }
    }
    
}
