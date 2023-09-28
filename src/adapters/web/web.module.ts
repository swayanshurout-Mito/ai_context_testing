import { Module} from '@nestjs/common';
import { ExampleExternalApiService } from './example-api.web';
@Module({
  imports: [],
  providers: [ExampleExternalApiService],
  exports: [ExampleExternalApiService]
})
export class WebModule { }
