import { Inject, Injectable } from "@nestjs/common";
import { ClientProxy } from "@nestjs/microservices";

@Injectable()
export class NotificationService {
    constructor(@Inject("NOTIFICATION_RMQ_SERVICE") private client: ClientProxy) {}

    testSendMessage(): any {
        return this.client.send("test-event", JSON.stringify({ message: "hello its me ashley" }));
    }
}
