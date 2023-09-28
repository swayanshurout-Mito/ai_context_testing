import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/mongo/client';

@Injectable()
export class MongoService extends PrismaClient implements OnModuleInit {
  constructor() {
    super();
  }

  async onModuleInit() {
    await this.$connect();
  }
}
