import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as twoFactor from "node-2fa";
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

        const success = await this.userService.saveTwoFactorSecret(email, newSecret.secret);

        if (!success) {
            return false;
        }

        const newToken = twoFactor.generateToken(newSecret.secret);

        // TODO: Send notification via notification services.

        return newToken?.token != null;
    }

    async validateTwoFactorToken(email: string, token: string): Promise<boolean> {
        const userSecret = await this.userService.getTwoFactorSecret(email);
        const tokenValidWindow: number = this.configService.get("TOKEN_WINDOW") ?? 1;
        const results = twoFactor.verifyToken(userSecret, token, tokenValidWindow);
        return results?.delta != null && results.delta == 0;
    }
}
