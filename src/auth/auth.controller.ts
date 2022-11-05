import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Param,
    Post,
    Query,
    Request,
    Response,
    UnauthorizedException,
    UseGuards,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Request as Req, Response as Res } from "express";
import { EmailPasswordDTO } from "../dto/email-password.dto";
import { LoginMethodCheckDTO } from "../dto/login-method-check.dto";
import { LoginMethodEnum } from "../dto/login-method.enum";
import { TokenRequestDTO } from "../dto/token-request.dto";
import { UserCreationDTO } from "../dto/user-creation.dto";
import { UserDTO } from "../dto/user.dto";
import { UserService } from "../user/user.service";
import { UtilHelper } from "../utils";
import { AuthService } from "./auth.service";
import { LoginAuthGuard } from "./guard/login-auth.guard";

@Controller("auth")
export class AuthController {
    private BASE_GATEWAY_URL: string;
    constructor(
        private readonly authService: AuthService,
        private readonly configService: ConfigService,
        private readonly userService: UserService,
    ) {
        this.BASE_GATEWAY_URL = UtilHelper.isProduction()
            ? configService.get("PRODUCTION_GATEWAY_URL") ?? ""
            : configService.get("BASE_GATEWAY_URL") ?? "";
    }

    @Get("user-signup-status/:id")
    async magicLinkUserSignUpCheck(@Param("id") userId: string): Promise<string> {
        return await this.userService.fetchEmailMagicLink(userId);
    }

    @Post("signup")
    async signupDetailsUpdate(@Body() requestBody: UserCreationDTO, @Response() res: Res): Promise<Res> {
        await this.authService.signup(requestBody);
        return res.status(200).send({ message: "Success" });
    }

    @UseGuards(LoginAuthGuard)
    @Post("login")
    async hostedLogin(@Request() req: Req, @Response() res: Res): Promise<Res> {
        const user: UserDTO = req.user as UserDTO;
        const email: string = user.email;

        await this.authService.generate2FAToken(email);

        return res.json({
            message: `2FA token has been sent to ${email}!`,
        });
    }

    @Get("generate-2fa-token/:email")
    async send2FAToken(@Param("email") email: string, @Response() res: Res): Promise<Res> {
        await this.authService.generate2FAToken(email);

        return res.send(`Successfully sent 2FA token to ${email}`);
    }

    @Post("validate-2fa-token")
    async validate2FAToken(@Body() requestBody: TokenRequestDTO, @Response() res: Res): Promise<Res> {
        const { email, token } = requestBody;
        const success: boolean = await this.authService.validate2FAToken(email, token);

        if (success) {
            return res.json({ token: await this.authService.generateJWTToken({ email: email }) });
        }

        throw new UnauthorizedException("Invalid or expired 2FA token.");
    }

    @Get("generate-jwt-token/:email")
    async generateJWTToken(@Param("email") email: string, @Response() res: Res) {
        return res.json({ token: await this.authService.generateJWTToken({ email: email }) });
    }

    @Post("validate-jwt-token")
    async validateJWTToken(
        @Body() requestBody: { token: string; loginMethod: LoginMethodEnum },
        @Response() res: Res,
    ): Promise<Res> {
        const { token, loginMethod } = requestBody;
        if (!loginMethod) {
            throw new BadRequestException("Login method not specified");
        }
        return res.json({ userDetails: await this.authService.checkJWTValidity(token, loginMethod) });
    }

    @Get("get-jwks-pubkey/:keyId")
    async getJwksKey(@Param("keyId") keyId: string, @Response() res: Res): Promise<Res> {
        return res.json({ signingKey: await this.authService.getJwksPublicKey(keyId) });
    }

    @Get("sso/login")
    ssoRedirect(@Request() req: Req, @Response() res: Res): Res {
        const clientId = this.configService.get("SSO_CLIENT_ID");
        const ssoBaseUrl = this.configService.get("SSO_BASE_URL");
        const callbackUri = encodeURI(`${this.BASE_GATEWAY_URL}/api/auth/sso/callback`);
        const scopes: string[] = this.configService.get("SSO_CLIENT_SCOPE")?.split(",") ?? [];
        const authUri = `${ssoBaseUrl}/oauth/authorize?client_id=${clientId}&redirect_uri=${callbackUri}&response_type=code&scope=${scopes.join(
            "+",
        )}`;
        return res.json({ redirectUrl: authUri });
    }

    @Get("sso/callback")
    async oauthCallback(@Request() req: Req, @Response() res: Res, @Query("code") authCode: string): Promise<Res> {
        if (!authCode) {
            throw new UnauthorizedException("Consent was not provided to web application.");
        }

        const callbackUri = encodeURI(`${this.BASE_GATEWAY_URL}/api/auth/sso/callback?code=${authCode}`);
        const jwtToken = await this.authService.ssoTokenRequest(authCode, callbackUri);
        const userDetails = await this.userService.fetchUserDetailsSSO(jwtToken);

        // Retrieve user information from Bank SSO and update DynamoDB.
        // Update everytime the user login as information might have changed after last login.
        await this.authService.updateSSOUserInfo(userDetails);

        // Redirect to organisation selection screen.
        const clientUrl = UtilHelper.isProduction()
            ? this.configService.get("PRODUCTION_CLIENT_URL") ?? ""
            : this.configService.get("BASE_CLIENT_URL") ?? "";

        const redirectUrl = clientUrl + `/organisations?jwtToken=${jwtToken}`;

        return res.json({ redirectUrl: redirectUrl });
    }

    @Post("auth0/login")
    async auth0Login(@Body() requestBody: EmailPasswordDTO, @Response() res: Res): Promise<Res> {
        const { email, password } = requestBody;
        return res.json({ token: await this.authService.auth0Login(email, password) });
    }

    @Post("validate-login-method")
    async checkLoginMethodValidity(@Body() requestBody: LoginMethodCheckDTO, @Response() res: Res): Promise<Res> {
        const success = await this.authService.checkUserLoginMethod(
            requestBody.organizationId,
            requestBody.loginMethod,
        );
        return res.json({ success: success });
    }
}
