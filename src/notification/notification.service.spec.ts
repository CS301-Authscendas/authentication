import { ConfigModule, ConfigService } from "@nestjs/config";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { Test, TestingModule } from "@nestjs/testing";
import { NotificationService } from "./notification.service";

describe("NotificationService", () => {
    let service: NotificationService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
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
                                    `${configService.get<string>(
                                        "RABBITMQ_TRANSPORT_METHOD",
                                    )}://${configService.get<string>("RABBITMQ_USER")}:${configService.get<string>(
                                        "RABBITMQ_PASSWORD",
                                    )}@${configService.get<string>("RABBITMQ_HOST")}:${configService.get<string>(
                                        "RABBITMQ_PORT",
                                    )}`,
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
        }).compile();

        service = module.get<NotificationService>(NotificationService);
    });

    it("should be defined", () => {
        expect(service).toBeDefined();
    });
});
