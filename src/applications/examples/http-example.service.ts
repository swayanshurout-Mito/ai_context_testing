import { Injectable } from '@nestjs/common';
import { AxiosResponse } from 'axios';
import { ExampleExternalApiService } from 'src/adapters/web/example-api.web';

@Injectable()
export class HttpExampleService {
    constructor( private readonly exampleExternalApiService: ExampleExternalApiService ) {}
    async getData(): Promise<any> {
        try {
            const response: AxiosResponse = await this.exampleExternalApiService.getData();

            return response?.data
        } catch(error) {
            throw error
        }
    }
}
