import { Controller, Get } from "@nestjs/common";
import { AppService } from "./app.service";

@Controller("auth")
export class AppController {
    constructor(private readonly appService: AppService) {}

    @Get("are-you-awake")
    healthCheck(): string {
        return this.appService.healthCheck();
    }
}
