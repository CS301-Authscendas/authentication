import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
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
                imports: [MqModule, ConfigModule],
                inject: [MqService, ConfigService],
                useFactory: (mqService: MqService, configService: ConfigService) =>
                    mqService.getClientProvider(configService.get("NOTIFICATION_QUEUE_NAME") ?? ""),
            },
        ]),
    ],
    providers: [NotificationService],
    exports: [NotificationService],
})
export class NotificationModule {}
