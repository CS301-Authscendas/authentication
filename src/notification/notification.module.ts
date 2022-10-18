import { Module } from "@nestjs/common";
import { ClientsModule } from "@nestjs/microservices";
import { MqModule } from "../mq/mq.module";
import { MqService } from "../mq/mq.service";
import { NotificationService } from "./notification.service";

@Module({
    imports: [
        MqModule,
        ClientsModule.registerAsync([
            {
                name: "NOTIFICATION_RMQ_SERVICE",
                imports: [MqModule],
                inject: [MqService],
                useFactory: (mqService: MqService) => mqService.getClientProvider("notification"),
            },
        ]),
    ],
    providers: [NotificationService],
    exports: [NotificationService],
})
export class NotificationModule {}
