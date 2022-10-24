import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { UserDTO } from "src/dto/user.dto";
import { UserService } from "src/user/user.service";

@Injectable()
export class JWTStrategy extends PassportStrategy(Strategy, "jwt") {
    constructor(private readonly userService: UserService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: "none", // public key is handled in JWT strategy.
        });
    }

    async validate(payload: any): Promise<UserDTO> {
        return await this.userService.fetchUserDetails(payload.email);
    }
}
