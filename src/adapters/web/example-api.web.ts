import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AxiosResponse } from 'axios';
import { HttpHandlerService } from '@raksul/josys-commons/packages/http';
import { LoggerService } from '@raksul/josys-commons/packages/logger';

@Injectable()
export class ExampleExternalApiService {
    constructor(
        private readonly configService: ConfigService,
        private readonly httpHandlerService: HttpHandlerService,
        private readonly loggerService: LoggerService,
    ) { }

    async getData(): Promise<AxiosResponse> {
        const url = this.urlBuilder();
        const headers = this.createHeaders();
        const response: AxiosResponse = await this.httpHandlerService.get(url, { headers });

        return response;
    }


    private createHeaders(): any {
        return {
            'Content-Type': this.configService.get('EXAMPLE_CONTENT_TYPE'),
        };
    }

    private urlBuilder(): string {
        return `${this.configService.get('EXAMPLE_BASE_URL')}/bpi/currentprice.json`
    }
}
