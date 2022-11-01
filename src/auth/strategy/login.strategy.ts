import { BadRequestException, Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { AuthService } from "../auth.service";

@Injectable()
export class LoginStrategy extends PassportStrategy(Strategy, "login") {
    constructor(private authService: AuthService) {
        super({ usernameField: "email" });
    }

    // Passport expects a validate() method with the following signature:
    // validate(username: string, password: string): any
    async validate(email: string, password: string): Promise<any> {
        if (!email || !password) {
            throw new BadRequestException("Missing email or password!");
        }

        return await this.authService.validateUserCredentials(email, password);
    }
}
