import { Injectable } from "@nestjs/common";

@Injectable()
export class UserService {
    async saveTwoFactorSecret(email: string, twoFactorSecret: string): Promise<boolean> {
        // TODO: Publish MQ message to Organizations to store twoFactorSecret.
        return email != null && twoFactorSecret != null;
    }

    async getTwoFactorSecret(email: string): Promise<string> {
        // TODO: Publish a MQ request to Organizations to retrieve twoFactorSecret.
        // TODO: Subscribe to receive twoFactorSecret of user.
        return email;
    }

    async signup(): Promise<string> {
        // Generate 2FA
        // 2FA authentication for email ownership
        // Fetch user via email to check if user has been seeded
        // Store user credentials in the database

        return "Hello";
    }
}
