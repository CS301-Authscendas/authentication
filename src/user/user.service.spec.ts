import { HttpModule } from "@nestjs/axios";
import { ConfigModule } from "@nestjs/config";
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
                        imports: [MqModule],
                        inject: [MqService],
                        useFactory: (mqService: MqService) => mqService.getClientProvider("user"),
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
