import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { NotificationService } from "./notification.service";

@Module({
    imports: [
        ClientsModule.registerAsync([
            {
                name: "NOTIFICATION_RMQ_SERVICE",
                imports: [ConfigModule],
                inject: [ConfigService],
                useFactory: async (configService: ConfigService) => ({
                    transport: Transport.RMQ,
                    options: {
                        urls: [
                            `${configService.get<string>("RABBITMQ_TRANSPORT_METHOD")}://${configService.get<string>(
                                "RABBITMQ_USER",
                            )}:${configService.get<string>("RABBITMQ_PASSWORD")}@${configService.get<string>(
                                "RABBITMQ_HOST",
                            )}:${configService.get<string>("RABBITMQ_PORT")}`,
                        ],
                        queue: "notification",
                        queueOptions: {
                            durable: true,
                        },
                    },
                }),
            },
        ]),
    ],
    providers: [NotificationService],
    exports: [NotificationService],
})
export class NotificationModule {}
