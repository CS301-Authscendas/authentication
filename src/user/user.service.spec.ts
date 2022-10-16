import { HttpModule } from "@nestjs/axios";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { Test, TestingModule } from "@nestjs/testing";
import { UserService } from "./user.service";

describe("UserService", () => {
    let service: UserService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            imports: [
                HttpModule,
                ConfigModule,
                ClientsModule.registerAsync([
                    {
                        name: "USER_RMQ_SERVICE",
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
            providers: [UserService],
        }).compile();

        service = module.get<UserService>(UserService);
    });

    it("should be defined", () => {
        expect(service).toBeDefined();
    });
});
