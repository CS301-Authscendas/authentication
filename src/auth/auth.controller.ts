import {
    Body,
    Controller,
    Get,
    Headers,
    Param,
    Post,
    Query,
    Request,
    Response,
    UnauthorizedException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Request as Req, Response as Res } from "express";
import { BankSSOUser } from "src/dto/bank-sso-user.dto";
import { LoginCredentialsDTO } from "src/dto/login-credentials.dto";
import { UserCreationDTO } from "src/dto/user-creation.dto";
import { TokenRequestDTO } from "../dto/token-request.dto";
import { UserService } from "../user/user.service";
import { AuthService } from "./auth.service";

@Controller("auth")
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly configService: ConfigService,
        private readonly userService: UserService,
    ) {}

    @Get("generate-2fa-token/:email")
    async send2FAToken(@Param("email") email: string, @Response() res: Res): Promise<Res> {
        await this.authService.generate2FAToken(email);

        return res.send(`Successfully sent 2FA token to ${email}`);
    }

    @Post("validate-2fa-token")
    async validate2FAToken(@Body() requestBody: TokenRequestDTO, @Response() res: Res): Promise<Res> {
        const success = await this.authService.validate2FAToken(requestBody.email, requestBody.token);

        if (success) {
            return res.send("Successfully validated 2FA token");
        }

        throw new UnauthorizedException("Invalid or expired 2FA token.");
    }

    @Get("signup-request-2fa-token/:email")
    async signup(@Param("email") email: string, @Response() res: Res): Promise<Res> {
        await this.authService.signupRequest2FAToken(email);
        return res.send(`Successfully sent 2FA token to ${email}`);
    }

    @Post("signup-details")
    async signupDetailsUpdate(@Body() requestBody: UserCreationDTO): Promise<boolean> {
        return await this.authService.signup(requestBody);
    }

    @Post("login")
    async hostedLogin(@Body() requestBody: LoginCredentialsDTO, @Response() res: Res): Promise<Res> {
        const { email, password } = requestBody;

        const token = await this.authService.hostedLogin(email, password);

        return res.set({ Authorization: token }).json({ message: "Successfully logged in!" });
    }

    @Get("sso/login")
    ssoRedirect(@Request() req: Req, @Response() res: Res): void {
        const clientId = this.configService.get("SSO_CLIENT_ID");
        const ssoBaseUrl = this.configService.get("SSO_BASE_URL");
        const callbackUri = encodeURI(`${req.protocol}://${req.get("host")}/auth/sso/oauth/callback`);
        const scopes: string[] = this.configService.get("SSO_CLIENT_SCOPE")?.split(",") ?? [];
        const authUri = `${ssoBaseUrl}/oauth/authorize?client_id=${clientId}&redirect_uri=${callbackUri}&response_type=code&scope=${scopes.join(
            "+",
        )}`;
        return res.redirect(authUri);
    }

    @Get("sso/oauth/callback")
    async oauthCallback(@Request() req: Req, @Response() res: Res, @Query("code") authCode: string): Promise<Res> {
        if (!authCode) {
            throw new UnauthorizedException("Consent was not provided to web application.");
        }

        const callbackUri = encodeURI(`${req.protocol}://${req.get("host")}${req.originalUrl}`);
        const jwtToken = await this.authService.ssoTokenRequest(authCode, callbackUri);
        const userDetails = await this.userService.fetchUserDetailsSSO(jwtToken);

        // Retrieve user information from Bank SSO and update DynamoDB.
        // Update everytime the user login as information might have changed after last login.
        await this.authService.updateSSOUserInfo(userDetails);

        // TODO: Figure out if we need to send login alert email here.

        return res.json({ message: "SSO sign in successful!", token: jwtToken });
    }

    @Get("sso/fetch-user-info")
    async fetchUserInfoSSO(@Headers("Authorization") authorizationToken: string): Promise<BankSSOUser> {
        // Note: authorizationToken should not include the 'Bearer' prefix.
        return await this.userService.fetchUserDetailsSSO(authorizationToken);
    }
}
