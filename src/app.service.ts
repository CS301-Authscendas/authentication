import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as twoFactor from "node-2fa";
import { UserDTO, UserStatus } from "./dto/user.dto";
import { NotificationService } from "./notification/notification.service";
import { UserService } from "./user/user.service";

@Injectable()
export class AppService {
    constructor(
        private readonly userService: UserService,
        private readonly notificationService: NotificationService,
        private readonly configService: ConfigService,
    ) {}

    async generate2FAToken(email: string): Promise<boolean> {
        const newSecret = twoFactor.generateSecret();

        if (newSecret == null || newSecret.secret == null) {
            return false;
        }

        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);

        const name = `${userDetails.firstName} ${userDetails.lastName}`;

        // Save 2FA secret via Organizations microservice.
        this.userService.saveTwoFactorSecret(email, newSecret.secret);

        const newToken = twoFactor.generateToken(newSecret.secret);

        if (!newToken?.token) {
            return false;
        }

        // Send 2FA token via Notifications microservice.
        this.notificationService.trigger2FATokenEmail(name, email, newToken.token);
        return true;
    }

    async validate2FAToken(email: string, token: string): Promise<boolean> {
        const userSecret = await this.userService.getTwoFactorSecret(email);

        if (!userSecret) {
            return false;
        }

        const tokenValidWindow: number = this.configService.get("TOKEN_WINDOW") ?? 1;
        const results = twoFactor.verifyToken(userSecret, token, tokenValidWindow);
        return results?.delta != null && results.delta == 0;
    }

    async signupRequest2FAToken(email: string): Promise<any> {
        // Fetch user, check if user has already signed up before.
        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);

        if (userDetails.status === UserStatus.Approved) {
            throw new Error("User has already signed up");
        }

        // Generate 2FA and send 2FA token.
        return await this.generate2FAToken(email);
    }
}
