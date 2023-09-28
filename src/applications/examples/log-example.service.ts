import { Injectable } from '@nestjs/common';
import { LoggerService } from '@raksul/josys-commons/packages/logger';

@Injectable()
export class LogExampleService {
    constructor( private readonly loggerService: LoggerService) {}
    async getData() {
        throw this.loggerService.badRequestException()
    }
}
