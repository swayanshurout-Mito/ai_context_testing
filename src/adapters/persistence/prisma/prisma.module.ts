import { Module } from '@nestjs/common';
import { MongoService } from './service/mongo.service';
import { MysqlService } from './service/mysql.service';
import { ExampleDAO } from './dao/example.dao';


@Module({
    imports: [],
    providers: [
        ExampleDAO,
        //--------Services-------//
        MongoService,
        MysqlService,
    ],
    exports: [
        ExampleDAO,
        MongoService,
        MysqlService,
    ]
})
export class PrismaModule { }
