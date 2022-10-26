import {
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
import { AuthGuard } from "@nestjs/passport";
import { Request as Req, Response as Res } from "express";
import { TokenRequestDTO } from "../dto/token-request.dto";
import { UserCreationDTO } from "../dto/user-creation.dto";
import { UserDTO } from "../dto/user.dto";
import { UserService } from "../user/user.service";
import { AuthService } from "./auth.service";

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

    @UseGuards(AuthGuard("login"))
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
    async validateJWTToken(@Body() requestBody: { token: string }, @Response() res: Res): Promise<Res> {
        const { token } = requestBody;
        return res.json({ token: await this.authService.checkJWTValidity(token) });
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

        const redirectUri =
            this.configService.get("NODE_ENV") === "production"
                ? this.configService.get("PRODUCTION_URL") + "/home"
                : "http://localhost:8000/home";

        return res.redirect(redirectUri + `?jwtToken=${jwtToken}`);
    }
}
