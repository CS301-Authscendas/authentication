import { ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { AuthGuard } from "@nestjs/passport";
import { BankSSOUser } from "src/dto/bank-sso-user.dto";
import { UserJSONPayload } from "src/dto/user-json-payload.dto";
import { UserJWTData } from "src/dto/user-jwt-data.dto";
import { UserDTO } from "src/dto/user.dto";
import { UserService } from "src/user/user.service";
import { AuthService } from "../auth.service";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
    constructor(
        private readonly authService: AuthService,
        private readonly userService: UserService,
        private readonly configService: ConfigService,
    ) {
        super();
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const authHeader: string = request.header("Authorization");
        const jwtToken: string = authHeader.replace("Bearer", "").trim();

        if (!authHeader) {
            return false;
        }

        // Check if token is an SSO token.
        if (this.authService.isJwtTokenValid(jwtToken, this.configService.get("SSO_PUBLIC_KEY") ?? "")) {
            const ssoUser: BankSSOUser = await this.userService.fetchUserDetailsSSO(jwtToken);
            const dbUser: UserDTO = await this.userService.fetchUserDetails(ssoUser.email);
            request.user = dbUser;

            return true;
        }

        // Check if token is an hosted login token.
        if (this.authService.isJwtTokenValid(jwtToken, this.configService.get("JWT_PUBLIC_KEY") ?? "")) {
            const jwtData: UserJWTData = this.authService.decodeJWTToken(jwtToken);
            const data: UserJSONPayload = jwtData.payload as UserJSONPayload;
            const dbUser: UserDTO = await this.userService.fetchUserDetails(data.email);
            request.user = dbUser;

            return true;
        }

        throw new UnauthorizedException("Invalid JWT Token.");
    }
}
