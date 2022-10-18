import { Body, Controller, Get, HttpException, HttpStatus, Param, Post, Response } from "@nestjs/common";
import { ResponseObjDTO } from "../dto/responseObj.dto";
import { TokenRequestDTO } from "../dto/token-request.dto";
import { AuthService } from "./auth.service";
import { Response as Res } from "express";

@Controller("auth")
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Get("generate-2fa-token/:email")
    async send2FAToken(@Param("email") email: string): Promise<ResponseObjDTO> {
        const success: boolean = await this.authService.generate2FAToken(email);

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
        const success = await this.authService.validate2FAToken(requestBody.email, requestBody.token);

        if (success) {
            return {
                statusCode: HttpStatus.ACCEPTED,
                message: "Successfully validated 2FA token",
            };
        }

        throw new HttpException("Invalid or expired 2FA token.", HttpStatus.FORBIDDEN);
    }

    @Get("signup-request-2fa-token/:email")
    async signup(@Param("email") email: string): Promise<boolean> {
        return await this.authService.signupRequest2FAToken(email);
    }

    @Post("signup-details")
    async signupDetailsUpdate(@Body() requestBody: any): Promise<boolean> {
        return await this.authService.signup(requestBody);
    }

    @Post("login")
    async hostedLogin(@Body() requestBody: any, @Response() res: Res): Promise<Res> {
        const { email, password } = requestBody;

        const token = await this.authService.hostedLogin(email, password);

        return res.set({ Authorization: token }).json({ message: "Successfully logged in!" });
    }
}
