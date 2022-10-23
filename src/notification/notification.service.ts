import { Inject, Injectable } from "@nestjs/common";
import { ClientProxy } from "@nestjs/microservices";
import { LoginEmailParamsDTO } from "src/dto/login-email-params.dto";
import { TokenEmailParamsDTO } from "../dto/token-email-params.dto";

@Injectable()
export class NotificationService {
    constructor(@Inject("NOTIFICATION_RMQ_SERVICE") private client: ClientProxy) {}

    trigger2FATokenEmail(username: string, email: string, token: string): void {
        const dataObj: TokenEmailParamsDTO = {
            name: username,
            email: email,
            code: token,
        };

        this.client.send("send_2FA_token_email", dataObj).subscribe();
    }

    triggerLoginAlertEmail(username: string, email: string): void {
        const dataObj: LoginEmailParamsDTO = {
            name: username,
            email: email,
        };

        this.client.send("send_login_alert_email", dataObj).subscribe();
    }
}
