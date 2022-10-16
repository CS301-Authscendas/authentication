import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as twoFactor from "node-2fa";
import { UserDTO } from "./dto/user.dto";
import { NotificationService } from "./notification/notification.service";
import { UserService } from "./user/user.service";

@Injectable()
export class AppService {
    constructor(
        private readonly userService: UserService,
        private readonly notificationService: NotificationService,
        private readonly configService: ConfigService,
    ) {}

    async generateTwoFactor(email: string): Promise<boolean> {
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

    async validateTwoFactorToken(email: string, token: string): Promise<boolean> {
        const userSecret = await this.userService.getTwoFactorSecret(email);

        if (!userSecret) {
            return false;
        }

        const tokenValidWindow: number = this.configService.get("TOKEN_WINDOW") ?? 1;
        const results = twoFactor.verifyToken(userSecret, token, tokenValidWindow);
        return results?.delta != null && results.delta == 0;
    }
}
