import { Body, Controller, Get, HttpCode, HttpException, HttpStatus, Param, Post } from "@nestjs/common";
import { AppService } from "./app.service";
import { ResponseObjDTO } from "./dto/responseObj.dto";
import { TokenRequestDTO } from "./dto/token-request.dto";
import { UserService } from "./user/user.service";

@Controller()
export class AppController {
    constructor(private userService: UserService, private appService: AppService) {}

    @Get("healthcheck")
    @HttpCode(200)
    healthCheck(): string {
        return "Auth service is awake!";
    }

    @Get("generate-2fa-token/:email")
    async send2FAToken(@Param("email") email: string): Promise<ResponseObjDTO> {
        const success: boolean = await this.appService.generate2FAToken(email);

        if (success) {
            return {
                statusCode: HttpStatus.ACCEPTED,
                message: "Successfully sent 2FA token",
            };
        }

        throw new HttpException("Error generating 2FA token", HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Post("validate-2fa-token")
    async validate2FAToken(@Body() requestBody: TokenRequestDTO): Promise<ResponseObjDTO> {
        const success = await this.appService.validate2FAToken(requestBody.email, requestBody.token);

        if (success) {
            return {
                statusCode: HttpStatus.ACCEPTED,
                message: "Successfully validated 2FA token",
            };
        }

        throw new HttpException("Invalid or expired 2FA token.", HttpStatus.FORBIDDEN);
    }

    @Get("signup-request-2fa-token/:email")
    async signup(@Param("email") email: string): Promise<ResponseObjDTO> {
        try {
            const res = await this.appService.signupRequest2FAToken(email);
            return res;
        } catch (error) {
            throw new HttpException((error as Error).message, HttpStatus.BAD_REQUEST);
        }
    }
}
