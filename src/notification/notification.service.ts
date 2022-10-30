import { Inject, Injectable } from "@nestjs/common";
import { ClientProxy } from "@nestjs/microservices";
import { SuccessEmailRegistrationDTO } from "../dto/success-email-registration.dto";
import { LoginEmailParamsDTO } from "../dto/login-email-params.dto";
import { TokenEmailParamsDTO } from "../dto/token-email-params.dto";

@Injectable()
export class NotificationService {
    constructor(@Inject("NOTIFICATION_RMQ_SERVICE") private client: ClientProxy) {}

    triggerRegistrationSuccessEmail(username: string, email: string): void {
        const dataObj: SuccessEmailRegistrationDTO = {
            name: username,
            email: email,
        };

        this.client.send("send_successful_registration_email", dataObj).subscribe();
    }

    // Function to trigger notification service to send 2FA token email to user.
    trigger2FATokenEmail(username: string, email: string, token: string): void {
        const dataObj: TokenEmailParamsDTO = {
            name: username,
            email: email,
            code: token,
        };

        this.client.send("send_2FA_token_email", dataObj).subscribe();
    }

    // Function to trigger notification service to send new login alert email to user.
    triggerLoginAlertEmail(username: string, email: string): void {
        const dataObj: LoginEmailParamsDTO = {
            name: username,
            email: email,
        };

        this.client.send("send_login_alert_email", dataObj).subscribe();
    }
}
