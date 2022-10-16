import { Body, Controller, Get, Param, Post } from "@nestjs/common";
import { AppService } from "./app.service";
import { TokenRequestDTO } from "./dto/token-request.dto";
import { NotificationService } from "./notification/notification.service";
import { UserService } from "./user/user.service";

@Controller()
export class AppController {
    constructor(
        private userService: UserService,
        private notificationService: NotificationService,
        private appService: AppService,
    ) {}

    @Get("healthcheck")
    healthCheck(): string {
        return "Auth service is awake!";
    }

    @Get("generate-2fa-token/:email")
    async send2FAToken(@Param("email") email: string): Promise<boolean> {
        return await this.appService.generateTwoFactor(email);
    }

    @Post("validate-2fa-token")
    async validate2FAToken(@Body() requestBody: TokenRequestDTO): Promise<boolean> {
        // return await this.appService.generateTwoFactor(email);
        return requestBody != null;
    }

    @Post("signup")
    async signup(): Promise<string> {
        return await this.userService.signup();
    }

    @Get("test-send")
    test(): Promise<string> {
        return this.notificationService.testSendMessage();
    }
}
