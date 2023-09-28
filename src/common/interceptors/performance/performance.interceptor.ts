import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from "@nestjs/common";
import { Observable, tap } from "rxjs";

@Injectable()
export class PerformanceMonitor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler<any>): Observable<any> | Promise<Observable<any>> {
        const ctx = context.switchToHttp();
        const request = ctx.getRequest();
        const response = ctx.getResponse();

        const startTime = Date.now();

        return next.handle().pipe(
            tap(()=> {
                const endTime = Date.now();
                const resTime = endTime - startTime;

                console.log(`${request.method} ${request.path} ${response.statuscode} ${resTime}ms`)
            })
        )
    }
}