import { Controller, Get } from "@nestjs/common";
import { UserService } from "./user/user.service";

@Controller()
export class AppController {
    constructor(private userService: UserService) {}

    @Get("healthcheck")
    healthCheck(): string {
        return "Auth service is awake!";
    }
}
