import { ClientsModule } from "@nestjs/microservices";
import { Test, TestingModule } from "@nestjs/testing";
import { MqModule } from "../mq/mq.module";
import { MqService } from "../mq/mq.service";
import { NotificationService } from "./notification.service";

describe("NotificationService", () => {
    let service: NotificationService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
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
        }).compile();

        service = module.get<NotificationService>(NotificationService);
    });

    it("should be defined", () => {
        expect(service).toBeDefined();
    });
});
