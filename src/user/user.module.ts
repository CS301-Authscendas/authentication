import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { UserService } from "./user.service";

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
                        queue: "user",
                        queueOptions: {
                            durable: true,
                        },
                    },
                }),
            },
        ]),
    ],
    providers: [UserService],
    exports: [UserService],
})
export class UserModule {}
