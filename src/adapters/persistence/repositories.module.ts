import { Module } from '@nestjs/common';
import { PrismaModule } from './prisma/prisma.module';
import { ExampleDBRepository } from './repositories/examples/db.repository';
;

@Module({
  imports: [PrismaModule],
  providers: [
    ExampleDBRepository
  ],
  exports: [ExampleDBRepository]
})
export class RepositoryModule { }
