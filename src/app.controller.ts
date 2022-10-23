import { Controller, Get, HttpCode } from "@nestjs/common";

@Controller()
export class AppController {
    @Get("healthcheck")
    @HttpCode(200)
    healthCheck(): string {
        return "Auth service is awake!";
    }
}
