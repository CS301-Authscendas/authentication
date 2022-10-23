import { HttpModule } from "@nestjs/axios";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { ClientsModule } from "@nestjs/microservices";
import { Test, TestingModule } from "@nestjs/testing";
import { MqModule } from "../mq/mq.module";
import { MqService } from "../mq/mq.service";
import { UserService } from "./user.service";

describe("UserService", () => {
    let service: UserService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            imports: [
                HttpModule,
                ConfigModule,
                MqModule,
                ClientsModule.registerAsync([
                    {
                        name: "USER_RMQ_SERVICE",
                        imports: [MqModule, ConfigModule],
                        inject: [MqService, ConfigService],
                        useFactory: (mqService: MqService, configService: ConfigService) =>
                            mqService.getClientProvider(configService.get("USER_QUEUE_NAME") ?? ""),
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
