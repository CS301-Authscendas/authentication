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
    constructor(
        private readonly authService: AuthService,
        private readonly configService: ConfigService,
        private readonly userService: UserService,
    ) {}

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

    @Get("sso/callback")
    async oauthCallback(@Request() req: Req, @Response() res: Res, @Query("code") authCode: string): Promise<void> {
        if (!authCode) {
            throw new UnauthorizedException("Consent was not provided to web application.");
        }

        const callbackUri = encodeURI(`${req.protocol}://${req.get("host")}${req.originalUrl}`);
        const jwtToken = await this.authService.ssoTokenRequest(authCode, callbackUri);
        const userDetails = await this.userService.fetchUserDetailsSSO(jwtToken);

        // Retrieve user information from Bank SSO and update DynamoDB.
        // Update everytime the user login as information might have changed after last login.
        await this.authService.updateSSOUserInfo(userDetails);

        // Redirect to organisation selection screen.
        const redirectUri = UtilHelper.isProduction()
            ? this.configService.get("PRODUCTION_URL") + "/organisations"
            : "http://localhost:8000/organisations";

        return res.redirect(redirectUri + `?jwtToken=${jwtToken}`);
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
