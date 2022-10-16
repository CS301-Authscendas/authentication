import { Inject, Injectable } from "@nestjs/common";
import { ClientProxy } from "@nestjs/microservices";
import { TokenEmailParamsDTO } from "src/dto/token-email-params.dto";

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
}
